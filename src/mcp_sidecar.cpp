#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "lattice_engine.hpp"
#include "generated_policy.hpp"
#include "seccomp_supervisor.hpp"
#include "landlock_sandbox.hpp"
#include <atomic>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__) && __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define MCP_GATE_HAVE_OPENAT2_H 1
#endif

// Linux 3.4+; some glibc versions do not define it in <sys/prctl.h>.
#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

namespace {

using mcp_lattice::LatticeEngine;

constexpr std::size_t kMaxLine = 1u << 20;

constexpr int kErrParse = -32700;
constexpr int kErrInvalidRequest = -32600;
constexpr int kErrInvalidParams = -32602;
constexpr int kErrPolicyDenied = -32001;
constexpr int kErrCanonicalization = -32002;
constexpr int kErrMethodBlocked = -32004;

namespace json {

struct Node {
  enum class Type : std::uint8_t { kNull, kBool, kNum, kStr, kArr, kObj };
  Type type = Type::kNull;
  bool b = false;
  std::string str;
  std::string raw;
  std::size_t begin = 0;
  std::size_t end = 0;
  std::vector<Node> items;
  std::vector<std::pair<std::string, Node>> members;

  const Node* find(std::string_view key) const {
    if (type != Type::kObj) return nullptr;
    for (const auto& kv : members) {
      if (kv.first == key) return &kv.second;
    }
    return nullptr;
  }
};

class Parser {
 public:
  Parser(std::string_view src, bool strict) : src_(src), strict_(strict) {}

  void skip_ws() {
    while (i_ < src_.size() &&
           (src_[i_] == ' ' || src_[i_] == '\t' || src_[i_] == '\r')) {
      ++i_;
    }
  }

  bool parse_value(Node& out, std::size_t depth) {
    if (depth > 64) return fail();
    skip_ws();
    if (i_ >= src_.size()) return fail();
    out = Node{};
    out.begin = i_;

    const char c = src_[i_];
    if (c == '{') return parse_obj(out, depth);
    if (c == '[') return parse_arr(out, depth);
    if (c == '"') {
      out.type = Node::Type::kStr;
      if (!parse_string(out.str)) return false;
    } else if (c == 't') {
      if (src_.compare(i_, 4, "true") != 0) return fail();
      i_ += 4;
      out.type = Node::Type::kBool;
      out.b = true;
    } else if (c == 'f') {
      if (src_.compare(i_, 5, "false") != 0) return fail();
      i_ += 5;
      out.type = Node::Type::kBool;
    } else if (c == 'n') {
      if (src_.compare(i_, 4, "null") != 0) return fail();
      i_ += 4;
      out.type = Node::Type::kNull;
    } else {
      if (src_[i_] == '-') ++i_;
      bool digits = false;
      while (i_ < src_.size()) {
        const char d = src_[i_];
        if (d >= '0' && d <= '9') {
          digits = true;
          ++i_;
        } else if (d == '.' || d == 'e' || d == 'E' || d == '+' || d == '-') {
          ++i_;
        } else {
          break;
        }
      }
      if (!digits) return fail();
      out.type = Node::Type::kNum;
    }
    out.end = i_;
    out.raw = std::string(src_.substr(out.begin, out.end - out.begin));
    return ok;
  }

  bool ok = true;

  void set_end_check() {
    skip_ws();
    ok = ok && (i_ == src_.size());
  }

 private:
  bool fail() {
    ok = false;
    return false;
  }

  bool parse_string(std::string& out) {
    ++i_;
    out.clear();
    while (i_ < src_.size()) {
      const auto c = static_cast<unsigned char>(src_[i_]);
      if (c == '"') {
        ++i_;
        return true;
      }
      if (c < 0x20 || c == 0x7F) return fail();
      if (c >= 0x80) {
        if (strict_) return fail();
        out += static_cast<char>(c);
        ++i_;
        continue;
      }
      if (c == '\\') {
        ++i_;
        if (i_ >= src_.size()) return fail();
        const char e = src_[i_++];
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            unsigned cp = 0;
            for (int k = 0; k < 4; ++k) {
              if (i_ >= src_.size()) return fail();
              const char h = src_[i_++];
              cp <<= 4;
              if (h >= '0' && h <= '9') cp |= static_cast<unsigned>(h - '0');
              else if (h >= 'a' && h <= 'f') cp |= static_cast<unsigned>(h - 'a' + 10);
              else if (h >= 'A' && h <= 'F') cp |= static_cast<unsigned>(h - 'A' + 10);
              else return fail();
            }
            if (cp >= 0x80 && strict_) return fail();
            out += (cp >= 0x80) ? '?' : static_cast<char>(cp);
            break;
          }
          default: return fail();
        }
        continue;
      }
      out += static_cast<char>(c);
      ++i_;
    }
    return fail();
  }

  bool parse_arr(Node& out, std::size_t depth) {
    out.type = Node::Type::kArr;
    ++i_;
    skip_ws();
    if (i_ < src_.size() && src_[i_] == ']') {
      ++i_;
      out.end = i_;
      out.raw = std::string(src_.substr(out.begin, out.end - out.begin));
      return ok;
    }
    while (ok) {
      Node item;
      if (!parse_value(item, depth + 1)) return false;
      out.items.push_back(std::move(item));
      skip_ws();
      if (i_ >= src_.size()) return fail();
      if (src_[i_] == ',') {
        ++i_;
        continue;
      }
      if (src_[i_] == ']') {
        ++i_;
        out.end = i_;
        out.raw = std::string(src_.substr(out.begin, out.end - out.begin));
        return ok;
      }
      return fail();
    }
    return false;
  }

  bool parse_obj(Node& out, std::size_t depth) {
    out.type = Node::Type::kObj;
    ++i_;
    skip_ws();
    if (i_ < src_.size() && src_[i_] == '}') {
      ++i_;
      out.end = i_;
      out.raw = std::string(src_.substr(out.begin, out.end - out.begin));
      return ok;
    }
    while (ok) {
      skip_ws();
      if (i_ >= src_.size() || src_[i_] != '"') return fail();
      std::string key;
      if (!parse_string(key)) return false;
      if (strict_) {
        for (const auto& kv : out.members) {
          if (kv.first == key) return fail();
        }
      }
      skip_ws();
      if (i_ >= src_.size() || src_[i_] != ':') return fail();
      ++i_;
      Node val;
      if (!parse_value(val, depth + 1)) return false;
      out.members.emplace_back(std::move(key), std::move(val));
      skip_ws();
      if (i_ >= src_.size()) return fail();
      if (src_[i_] == ',') {
        ++i_;
        continue;
      }
      if (src_[i_] == '}') {
        ++i_;
        out.end = i_;
        out.raw = std::string(src_.substr(out.begin, out.end - out.begin));
        return ok;
      }
      return fail();
    }
    return false;
  }

  std::string_view src_;
  bool strict_;
  std::size_t i_ = 0;
};

bool parse(const std::string& line, Node& out, bool strict) {
  Parser p(line, strict);
  if (!p.parse_value(out, 0)) return false;
  p.set_end_check();
  return p.ok;
}

}  // namespace json

bool write_all(int fd, std::string_view data) {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
}

bool emit(int fd, std::string_view msg) {
  return write_all(fd, msg) && write_all(fd, "\n");
}

class LineReader {
 public:
  explicit LineReader(int fd) : fd_(fd) {}

  bool next(std::string& line) {
    line.clear();
    for (;;) {
      const std::size_t pos = pending_.find('\n');
      if (pos != std::string::npos) {
        line = pending_.substr(0, pos);
        pending_.erase(0, pos + 1);
        return true;
      }
      if (pending_.size() > kMaxLine) return false;
      char buf[8192];
      const ssize_t n = ::read(fd_, buf, sizeof buf);
      if (n == 0) return false;
      if (n < 0) {
        if (errno == EINTR) continue;
        return false;
      }
      pending_.append(buf, static_cast<std::size_t>(n));
    }
  }

 private:
  int fd_;
  std::string pending_;
};

std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out += '"';
  for (const auto u : s) {
    const auto c = static_cast<unsigned char>(u);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20 || c >= 0x80) {
          char b[8];
          std::snprintf(b, sizeof b, "\\u%04X", static_cast<unsigned>(c));
          out += b;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  out += '"';
  return out;
}

std::string make_error(const std::string& id_raw, int code, std::string_view msg) {
  std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
  out += id_raw.empty() ? "null" : id_raw;
  out += ",\"error\":{\"code\":";
  out += std::to_string(code);
  out += ",\"message\":";
  out += json_escape(msg);
  out += "}}";
  return out;
}

#if defined(__linux__) && !defined(MCP_GATE_HAVE_OPENAT2_H)
struct open_how {
  std::uint64_t flags;
  std::uint64_t mode;
  std::uint64_t resolve;
};
constexpr std::uint64_t RESOLVE_NO_MAGICLINKS = 0x02;
constexpr std::uint64_t RESOLVE_NO_SYMLINKS = 0x04;
constexpr std::uint64_t RESOLVE_BENEATH = 0x08;
#endif

bool is_clean_ascii_path(std::string_view p) {
  for (const char c : p) {
    const auto u = static_cast<unsigned char>(c);
    if (u >= 0x80 || u < 0x20 || u == 0x7F) return false;
  }
  return true;
}

std::optional<std::string> readlink_fd(int fd) {
  char linkbuf[64];
  std::snprintf(linkbuf, sizeof linkbuf, "/proc/self/fd/%d", fd);
  char path[4096];
  const ssize_t n = ::readlink(linkbuf, path, sizeof path - 1);
  if (n <= 0 || static_cast<std::size_t>(n) >= sizeof path - 1) return std::nullopt;
  path[n] = '\0';
  return std::string(path);
}

std::optional<std::string> canonicalize_nofollow(int ws_fd, std::string_view rel) {
  int cur = ::dup(ws_fd);
  if (cur < 0) return std::nullopt;
  std::optional<std::string> result;
  std::size_t i = 0;
  bool ok = true;
  while (i < rel.size() && ok) {
    while (i < rel.size() && rel[i] == '/') ++i;
    const std::size_t j = i;
    while (i < rel.size() && rel[i] != '/') ++i;
    if (j == i) break;
    const std::string comp(rel.substr(j, i - j));
    if (comp == ".") continue;
    if (comp == "..") {
      ok = false;
      break;
    }
    const int next = ::openat(cur, comp.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0) {
      ok = false;
      break;
    }
    struct stat st {};
    const bool is_last = (i >= rel.size());
    if (::fstat(next, &st) != 0 ||
        (!is_last && !S_ISDIR(st.st_mode)) ||
        (is_last && !S_ISREG(st.st_mode))) {
      ::close(next);
      ok = false;
      break;
    }
    ::close(cur);
    cur = next;
  }
  if (ok) result = readlink_fd(cur);
  ::close(cur);
  return result;
}

namespace detail {
[[nodiscard]] constexpr char ascii_lower(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + ('a' - 'A')) : ch;
}
[[nodiscard]] constexpr bool ends_with_icase(std::string_view str, std::string_view suffix) noexcept {
  if (str.size() < suffix.size()) return false;
  const std::size_t offset = str.size() - suffix.size();
  for (std::size_t i = 0; i < suffix.size(); ++i) {
    if (ascii_lower(str[offset + i]) != ascii_lower(suffix[i])) return false;
  }
  return true;
}
}  // namespace detail

[[nodiscard]] bool is_safe_workspace_path(std::string_view path, std::string_view safe_prefix) noexcept {
  if (safe_prefix.size() < 2 || safe_prefix.front() != '/' || safe_prefix.back() != '/') return false;
  if (path.size() <= safe_prefix.size() || path.back() == '/') return false;
  if (path.substr(0, safe_prefix.size()) != safe_prefix) return false;
  if (path.find("..") != std::string_view::npos ||
      path.find("//") != std::string_view::npos ||
      path.find("/.") != std::string_view::npos) {
    return false;
  }
  constexpr std::array<std::string_view, 6> blocked_suffixes = {
      ".pem", ".key", ".p12", ".sql", ".env", ".kdbx"};
  for (const auto suffix : blocked_suffixes) {
    if (detail::ends_with_icase(path, suffix)) return false;
  }
  return true;
}

std::optional<std::string> canonicalize_path(
    int ws_fd,
    const std::string& path,
    std::string_view safe_prefix
) {
  if (!is_clean_ascii_path(path)) return std::nullopt;
  if (path.size() <= safe_prefix.size()) return std::nullopt;
  if (path.compare(0, safe_prefix.size(), safe_prefix) != 0) return std::nullopt;

  const std::string rel = path.substr(safe_prefix.size());
  if (rel.empty() || rel[0] == '/') return std::nullopt;

  std::optional<std::string> res;
#if defined(__linux__) && defined(SYS_openat2)
  {
    open_how how {};
    how.flags = static_cast<std::uint64_t>(O_PATH) |
                static_cast<std::uint64_t>(O_NOFOLLOW) |
                static_cast<std::uint64_t>(O_CLOEXEC);
    how.mode = 0;
    how.resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;
    const long fd = ::syscall(SYS_openat2, ws_fd, rel.c_str(), &how, sizeof how);
    if (fd >= 0) {
      struct stat st {};
      if (::fstat(static_cast<int>(fd), &st) == 0 && S_ISREG(st.st_mode)) {
        res = readlink_fd(static_cast<int>(fd));
      } else {
        ::close(static_cast<int>(fd));
        return std::nullopt;
      }
      ::close(static_cast<int>(fd));
    } else if (errno != ENOSYS && errno != EINVAL) {
      return std::nullopt;
    }
  }
#endif
  if (!res) {
    res = canonicalize_nofollow(ws_fd, rel);
  }
  if (!res || !is_clean_ascii_path(*res)) return std::nullopt;
  if (res->size() <= safe_prefix.size() ||
      res->compare(0, safe_prefix.size(), safe_prefix) != 0) {
    return std::nullopt;
  }
  return res;
}

constexpr std::array<std::string_view, 10> kVettedCommands = {
    "ls", "cat", "head", "tail", "grep",
    "find", "wc", "diff", "stat", "sha256sum"};

constexpr std::array<std::string_view, 8> kFindBlockedFlags = {
    "-exec", "-execdir", "-ok", "-okdir", "-delete",
    "-fprint", "-fprintf", "-fls"};

// v0.6 (H4 de-shell): bash_workspace takes a TYPED argv array, not a shell
// command string. The client supplies JSON {"argv": ["ls", "-l", "."]}; the
// gate vets each element as one argv word and forwards the array verbatim;
// the downstream executor contract is execv(3)-family on that exact array --
// no shell is ever consulted, so the gate's verdict and the executor's
// behavior cannot disagree about grammar (the v0.5 string-parser semantic
// gap is structurally gone). Bounded to keep forwarded frames sane.
constexpr std::size_t kMaxArgvElements = 256;
constexpr std::size_t kMaxArgvElementBytes = 1024;

bool token_hits_symlink(int ws_fd, std::string_view t, std::string_view safe_prefix) {
  std::string rel;
  if (!t.empty() && t[0] == '/') {
    if (t.size() <= safe_prefix.size() || t.substr(0, safe_prefix.size()) != safe_prefix) {
      return true;
    }
    rel = std::string(t.substr(safe_prefix.size()));
  } else {
    rel = std::string(t);
  }
  if (rel.empty() || rel == ".") return false;
#if defined(__linux__) && defined(SYS_openat2)
  open_how how {};
  how.flags = static_cast<std::uint64_t>(O_PATH) |
              static_cast<std::uint64_t>(O_NOFOLLOW) |
              static_cast<std::uint64_t>(O_CLOEXEC);
  how.mode = 0;
  how.resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;
  const long fd = ::syscall(SYS_openat2, ws_fd, rel.c_str(), &how, sizeof how);
  if (fd >= 0) {
    struct stat st {};
    const bool is_lnk = (::fstat(static_cast<int>(fd), &st) != 0 || S_ISLNK(st.st_mode));
    ::close(static_cast<int>(fd));
    return is_lnk;
  }
  if (errno == ELOOP || errno == EXDEV) return true;
  if (errno == ENOENT || errno == ENOTDIR) return false;
#endif
  struct stat st {};
  if (::fstatat(ws_fd, rel.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode)) {
    return true;
  }
  return false;
}

[[nodiscard]] bool argv_element_printable_ascii(std::string_view t) noexcept {
  for (const char c : t) {
    const auto u = static_cast<unsigned char>(c);
    if (u >= 0x80 || u < 0x20 || u == 0x7F) return false;
  }
  return true;
}

// v0.6 (H4): content vetting of a shape-valid typed argv array. The caller
// has already established the shape (non-empty JSON array of non-empty
// printable-ASCII strings within the size bounds). A false return means the
// CONTENT is unvetted: the call is classified UNKNOWN and hits the exact
// v0.5 policy path (deny -32001 plus permanent session absorption). With no
// shell in the picture, metacharacters are no longer grammar -- a filename
// containing ';' or '|' is ordinary data -- so the v0.5 character denylist
// and whitespace tokenizer are deleted rather than ported. What remains are
// the rules that still mean something one-argv-word-at-a-time.
[[nodiscard]] bool is_vetted_argv(const std::vector<std::string>& argv,
                                  std::string_view safe_prefix, int ws_fd) {
  if (argv.empty()) return false;

  bool program_ok = false;
  for (const auto v : kVettedCommands) {
    if (argv[0] == v) {
      program_ok = true;
      break;
    }
  }
  if (!program_ok) return false;

  if (argv[0] == "find") {
    for (const auto& t : argv) {
      for (const auto bad : kFindBlockedFlags) {
        if (t == bad) return false;
      }
    }
  }

  for (std::size_t k = 1; k < argv.size(); ++k) {
    const std::string_view t = argv[k];
    // Traversal substrings are rejected in every element, flags included
    // (v0.5 checked them over the whole command string; per-element keeps
    // the same coverage without the string parse).
    if (t.find("..") != std::string_view::npos ||
        t.find("/.") != std::string_view::npos) {
      return false;
    }
    if (t[0] == '-') {
      // Flags must stay flags: no embedded paths or assignments.
      if (t.find('/') != std::string_view::npos ||
          t.find('=') != std::string_view::npos) {
        return false;
      }
      continue;
    }
    if (t != "." && t[0] == '.') return false;  // dotfiles
    constexpr std::array<std::string_view, 6> blocked_suffixes = {
        ".pem", ".key", ".p12", ".sql", ".env", ".kdbx"};
    for (const auto suffix : blocked_suffixes) {
      if (detail::ends_with_icase(t, suffix)) return false;
    }
    if (t[0] == '/') {
      if (safe_prefix.empty() || t.size() <= safe_prefix.size()) return false;
      if (t.substr(0, safe_prefix.size()) != safe_prefix) return false;
    }
    if (token_hits_symlink(ws_fd, t, safe_prefix)) return false;
  }
  return true;
}

enum class ToolCategory : std::uint8_t {
  SAFE_READ = 0,
  SENSITIVE_READ,
  NETWORK_OUTBOUND,
  EXEC_WORKSPACE,
  UNKNOWN
};

struct Classification {
  ToolCategory category = ToolCategory::UNKNOWN;
  bool canonical_ok = true;
  // v0.6 (H4): argv-contract violations are client contract errors, not
  // policy events. shape_ok == false short-circuits the lattice entirely:
  // the call is refused with -32602, nothing is forwarded, and the session
  // state is untouched (a malformed frame must not cost the client the
  // session). Well-formed but unvetted content keeps the v0.5 UNKNOWN path.
  bool shape_ok = true;
  std::string shape_msg;
  std::string forward_arg;
  std::vector<std::string> forward_argv;
};

Classification classify_for_gate(std::string_view tool, const json::Node* arguments,
                                 std::string_view safe_prefix, int ws_fd) {
  Classification out;
  const json::Node* arg = nullptr;
  if (arguments != nullptr && arguments->type == json::Node::Type::kObj) {
    arg = arguments->find((tool == "read_file") ? "path" : "url");
  }
  const bool have_arg = (arg != nullptr && arg->type == json::Node::Type::kStr);

  if (tool == "read_file") {
    const std::string raw_path = have_arg ? arg->str : std::string();
    auto canon = canonicalize_path(ws_fd, raw_path, safe_prefix);
    if (!canon) {
      out.category = ToolCategory::SENSITIVE_READ;
      out.canonical_ok = false;
      return out;
    }
    out.forward_arg = *canon;
    out.category = is_safe_workspace_path(*canon, safe_prefix)
                       ? ToolCategory::SAFE_READ
                       : ToolCategory::SENSITIVE_READ;
    return out;
  }
  if (tool == "http_fetch" || tool == "fetch_url") {
    out.forward_arg = have_arg ? arg->str : std::string();
    out.category = ToolCategory::NETWORK_OUTBOUND;
    return out;
  }
  if (tool == "bash_workspace") {
    // v0.6 (H4): typed argv-array contract. The 'command' shell string is
    // gone; shape errors are refused cleanly, content violations stay
    // policy denials with session absorption.
    const json::Node* argv_n = nullptr;
    const json::Node* legacy_n = nullptr;
    if (arguments != nullptr && arguments->type == json::Node::Type::kObj) {
      argv_n = arguments->find("argv");
      legacy_n = arguments->find("command");
    }
    const bool legacy_command = (legacy_n != nullptr && argv_n == nullptr);
    const char* base_hint =
        "bash_workspace requires 'argv': a non-empty JSON array of "
        "printable-ASCII strings (max 256 elements, 1024 bytes each)";
    if (legacy_command) {
      out.shape_ok = false;
      out.shape_msg = std::string(base_hint) +
          "; shell command strings ('command') are no longer accepted -- "
          "split the command into words and pass them as typed argv";
      return out;
    }
    if (argv_n == nullptr) {
      out.shape_ok = false;
      out.shape_msg = base_hint;
      return out;
    }
    if (argv_n->type != json::Node::Type::kArr) {
      out.shape_ok = false;
      out.shape_msg = std::string(base_hint) + "; got a non-array 'argv'";
      return out;
    }
    if (argv_n->items.empty()) {
      out.shape_ok = false;
      out.shape_msg = std::string(base_hint) + "; 'argv' must not be empty";
      return out;
    }
    if (argv_n->items.size() > kMaxArgvElements) {
      out.shape_ok = false;
      out.shape_msg = std::string(base_hint) +
          "; too many elements (limit 256)";
      return out;
    }
    std::vector<std::string> argv;
    argv.reserve(argv_n->items.size());
    for (const auto& item : argv_n->items) {
      if (item.type != json::Node::Type::kStr) {
        out.shape_ok = false;
        out.shape_msg = std::string(base_hint) +
            "; every element must be a JSON string";
        return out;
      }
      if (item.str.empty()) {
        out.shape_ok = false;
        out.shape_msg = std::string(base_hint) +
            "; elements must be non-empty";
        return out;
      }
      if (item.str.size() > kMaxArgvElementBytes) {
        out.shape_ok = false;
        out.shape_msg = std::string(base_hint) +
            "; element exceeds 1024 bytes";
        return out;
      }
      if (!argv_element_printable_ascii(item.str)) {
        out.shape_ok = false;
        out.shape_msg = std::string(base_hint) +
            "; elements must be printable 7-bit ASCII (control bytes, DEL,"
            " and non-ASCII -- including \\u escapes decoding to them -- are"
            " rejected; embedded NUL would truncate the word at exec time)";
        return out;
      }
      argv.push_back(item.str);
    }
    if (!is_vetted_argv(argv, safe_prefix, ws_fd)) {
      out.category = ToolCategory::UNKNOWN;
      return out;
    }
    out.forward_argv = std::move(argv);
    out.category = ToolCategory::EXEC_WORKSPACE;
    return out;
  }
  out.category = ToolCategory::UNKNOWN;
  return out;
}

std::string build_forwarded_call(const std::string& id_raw, bool is_notification,
                                 std::string_view tool, const Classification& cls) {
  std::string out = "{\"jsonrpc\":\"2.0\"";
  if (!is_notification) {
    out += ",\"id\":";
    out += id_raw.empty() ? "null" : id_raw;
  }
  out += ",\"method\":\"tools/call\",\"params\":{\"name\":";
  out += json_escape(tool);
  out += ",\"arguments\":{";
  if (tool == "read_file") {
    out += "\"path\":";
    out += json_escape(cls.forward_arg);
  } else if (tool == "bash_workspace") {
    // v0.6 (H4): forward the vetted typed array verbatim. The downstream
    // contract is direct execv(3) on this exact array -- never a shell.
    out += "\"argv\":[";
    for (std::size_t i = 0; i < cls.forward_argv.size(); ++i) {
      if (i != 0) out += ',';
      out += json_escape(cls.forward_argv[i]);
    }
    out += ']';
  } else {
    out += "\"url\":";
    out += json_escape(cls.forward_arg);
  }
  out += "}}}";
  return out;
}

struct Child {
  pid_t pid = -1;
  int to_child = -1;
  int from_child = -1;
  int seccomp_fd = -1;
  int handoff_sock = -1;
};

bool spawn_downstream(const std::vector<std::string>& cmdv, Child& out,
                      bool enable_seccomp, bool enable_landlock,
                      const std::string& safe_prefix) {
  int sv[2] = {-1, -1};
  if (enable_seccomp) {
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) return false;
  }
  int in_pipe[2];
  int out_pipe[2];
  int exec_pipe[2];
  if (::pipe(in_pipe) != 0) {
    if (enable_seccomp) { ::close(sv[0]); ::close(sv[1]); }
    return false;
  }
  if (::pipe(out_pipe) != 0) {
    ::close(in_pipe[0]); ::close(in_pipe[1]);
    if (enable_seccomp) { ::close(sv[0]); ::close(sv[1]); }
    return false;
  }
  if (::pipe(exec_pipe) != 0) {
    ::close(in_pipe[0]); ::close(in_pipe[1]);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    if (enable_seccomp) { ::close(sv[0]); ::close(sv[1]); }
    return false;
  }
  ::fcntl(in_pipe[1], F_SETFD, FD_CLOEXEC);
  ::fcntl(out_pipe[0], F_SETFD, FD_CLOEXEC);
  ::fcntl(exec_pipe[0], F_SETFD, FD_CLOEXEC);
  ::fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);

  std::vector<char*> argv;
  argv.reserve(cmdv.size() + 1);
  for (const auto& s : cmdv) argv.push_back(const_cast<char*>(s.c_str()));
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(in_pipe[0]); ::close(in_pipe[1]);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    ::close(exec_pipe[0]); ::close(exec_pipe[1]);
    if (enable_seccomp) { ::close(sv[0]); ::close(sv[1]); }
    return false;
  }
  if (pid == 0) {
    ::dup2(in_pipe[0], STDIN_FILENO);
    ::dup2(out_pipe[1], STDOUT_FILENO);
    ::close(in_pipe[0]); ::close(in_pipe[1]);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    ::close(exec_pipe[0]);
    auto fail_child = [&](std::uint8_t code) {
      const ssize_t ignored = ::write(exec_pipe[1], &code, 1);
      (void)ignored;
      ::_exit(code);
    };
    if (enable_landlock) {
      if (!mcp_landlock::child_apply_landlock(safe_prefix.c_str())) {
        fail_child(126);
      }
    }
    if (enable_seccomp) {
      ::close(sv[0]);
      if (!mcp_seccomp::child_install_and_handoff(sv[1])) {
        fail_child(126);
      }
      ::close(sv[1]);
    }
    ::execvp(argv[0], argv.data());
    fail_child(127);
  }
  ::close(in_pipe[0]);
  ::close(out_pipe[1]);
  ::close(exec_pipe[1]);
  if (enable_seccomp) {
    ::close(sv[1]);
    out.seccomp_fd = mcp_seccomp::parent_fetch_listener_fd(sv[0], pid);
    if (out.seccomp_fd < 0) {
      ::close(sv[0]);
      ::close(exec_pipe[0]);
      ::close(in_pipe[1]);
      ::close(out_pipe[0]);
      ::kill(pid, SIGKILL);
      ::waitpid(pid, nullptr, 0);
      return false;
    }
    out.handoff_sock = sv[0];
  }
  // In non-seccomp mode, wait for EOF on the CLOEXEC exec_pipe to confirm
  // child Landlock setup and execvp() succeeded synchronously.
  // In seccomp mode, execve is USER_NOTIF-mediated (handled by Supervisor
  // after spawn_downstream() returns), and parent_fetch_listener_fd() above
  // already confirmed Landlock + seccomp installation succeeded.
  if (!enable_seccomp) {
    std::uint8_t child_err = 0;
    ssize_t er = 0;
    do {
      er = ::read(exec_pipe[0], &child_err, 1);
    } while (er < 0 && errno == EINTR);
    ::close(exec_pipe[0]);
    if (er > 0) {
      ::close(in_pipe[1]);
      ::close(out_pipe[0]);
      ::waitpid(pid, nullptr, 0);
      return false;
    }
  } else {
    ::close(exec_pipe[0]);
  }
  out.pid = pid;
  out.to_child = in_pipe[1];
  out.from_child = out_pipe[0];
  return true;
}

bool method_allowed(std::string_view m) {
  constexpr std::array<std::string_view, 6> kPass = {
      "initialize", "ping", "tools/list", "tools/call",
      "initialized", "notifications/initialized"};
  for (const auto k : kPass) {
    if (m == k) return true;
  }
  return false;
}

enum class RelayResult { kOk, kLost };

bool id_matches(const json::Node& id, const std::string& id_raw) {
  if (id.raw == id_raw) return true;
  if (id.type == json::Node::Type::kNum) {
    const double a = std::strtod(id.raw.c_str(), nullptr);
    const double b = std::strtod(id_raw.c_str(), nullptr);
    return a == b;
  }
  return false;
}

RelayResult relay_matching(LineReader& child, const std::string& id_raw) {
  std::string line;
  while (child.next(line)) {
    json::Node msg;
    if (!json::parse(line, msg, /*strict=*/false)) {
      std::fprintf(stderr, "[mcp-dfa-gate] dropped unparseable downstream output\n");
      continue;
    }
    const json::Node* method = msg.find("method");
    const json::Node* id = msg.find("id");
    if (method != nullptr || id == nullptr) {
      std::fprintf(stderr, "[mcp-dfa-gate] dropped downstream notification\n");
      continue;
    }
    if (!id_matches(*id, id_raw)) {
      std::fprintf(stderr, "[mcp-dfa-gate] dropped mismatched downstream response\n");
      continue;
    }
    if (!emit(STDOUT_FILENO, line)) return RelayResult::kLost;
    return RelayResult::kOk;
  }
  return RelayResult::kLost;
}

// ---- v0.5: local-filesystem pin (audit: netfs mmap writeback exfiltration) ----
// A workspace on a network filesystem (NFS/CIFS/9P/CEPH/FUSE) lets a tainted
// process exfiltrate via mmap(MAP_SHARED) dirty-page writeback performed by
// kernel helper threads, which never traverse the downstream seccomp filter.
// Refuse to start unless the workspace is on a local filesystem. Operators can
// explicitly accept the residual with MCP_GATE_ALLOW_NETFS=1.

struct FsMagicEntry {
  std::uint64_t magic;
  const char* name;
};

constexpr std::array<FsMagicEntry, 7> kLocalFsMagics = {{
    {0xEF53, "ext2/ext3/ext4"},
    {0x58465342, "xfs"},
    {0x9123683E, "btrfs"},
    {0xF2F52010, "f2fs"},
    {0x01021994, "tmpfs"},
    {0x858458F6, "ramfs"},
    {0x794C7630, "overlayfs"},
}};

constexpr std::array<FsMagicEntry, 9> kKnownNonLocalFsMagics = {{
    {0x6969, "NFS"},
    {0xFF534D42, "CIFS/SMB"},
    {0xFE534D42, "SMB2"},
    {0x65735546, "FUSE"},
    {0x09061997, "9P"},
    {0x00C36400, "CEPH"},
    {0x6B414653, "AFS"},
    {0x564C, "NCP"},
    {0x9FA0, "procfs"},
}};

// Returns true when the workspace root is on a local filesystem. Any statfs
// failure is fail-closed. `why` receives the fs name (or the error).
bool workspace_fs_is_local(const char* path, std::string* why) {
  struct statfs sfs {};
  if (::statfs(path, &sfs) != 0) {
    *why = std::string("statfs failed: ") + std::strerror(errno);
    return false;
  }
  const std::uint64_t magic =
      static_cast<std::uint64_t>(static_cast<unsigned long>(sfs.f_type));
  for (const auto& e : kLocalFsMagics) {
    if (e.magic == magic) {
      *why = e.name;
      return true;
    }
  }
  *why = "unsupported (non-local or unknown)";
  for (const auto& e : kKnownNonLocalFsMagics) {
    if (e.magic == magic) {
      *why = e.name;
      break;
    }
  }
  return false;
}

bool prefix_self_check(const std::string& safe_prefix) {
  if (safe_prefix.size() < 2 || safe_prefix.front() != '/' || safe_prefix.back() != '/') {
    return false;
  }
  for (const char c : safe_prefix) {
    const auto u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7F || c == '\\') return false;
  }
  if (safe_prefix.find("..") != std::string::npos) return false;
  LatticeEngine probe;
  const auto r = probe.inspect_tool("read_file", false);
  return r.allowed;
}

}  // namespace

int main(int argc, char** argv) {
  ::signal(SIGPIPE, SIG_IGN);

  std::string safe_prefix = "/workspace/public/";
  std::vector<std::string> downstream;
  {
    bool seen_ddash = false;
    for (int i = 1; i < argc; ++i) {
      const std::string a = argv[i];
      if (!seen_ddash && a == "--") {
        seen_ddash = true;
        continue;
      }
      if (seen_ddash) downstream.push_back(a);
      else safe_prefix = a;
    }
    if (downstream.empty()) {
      std::fprintf(stderr, "usage: mcp-dfa-gate [SAFE_PREFIX] -- DOWNSTREAM argv...\n");
      return 2;
    }
  }
  if (safe_prefix.empty() || safe_prefix[0] != '/') {
    std::fprintf(stderr, "[mcp-dfa-gate] SAFE_PREFIX must be an absolute path\n");
    return 2;
  }
  if (safe_prefix.back() != '/') safe_prefix += '/';
  if (!prefix_self_check(safe_prefix)) {
    std::fprintf(stderr, "[mcp-dfa-gate] SAFE_PREFIX rejected by startup self-check\n");
    return 2;
  }

  const int ws_fd = ::open(safe_prefix.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (ws_fd < 0) {
    std::fprintf(stderr, "[mcp-dfa-gate] cannot open workspace root '%s': %s\n",
                 safe_prefix.c_str(), std::strerror(errno));
    return 2;
  }

  // v0.5: fail closed on non-local workspace filesystems (mmap writeback
  // exfiltration bypasses syscall mediation entirely).
  {
    std::string fs_name;
    if (!workspace_fs_is_local(safe_prefix.c_str(), &fs_name)) {
      const char* allow = std::getenv("MCP_GATE_ALLOW_NETFS");
      if (allow == nullptr || std::strcmp(allow, "1") != 0) {
        std::fprintf(stderr,
                     "[mcp-dfa-gate] workspace '%s' is not on a local filesystem "
                     "(type: %s). Network/special filesystems permit mmap writeback "
                     "exfiltration that bypasses syscall mediation. Refusing to start "
                     "(set MCP_GATE_ALLOW_NETFS=1 to accept this risk).\n",
                     safe_prefix.c_str(), fs_name.c_str());
        ::close(ws_fd);
        return 2;
      }
      std::fprintf(stderr,
                   "[mcp-dfa-gate] WARNING: MCP_GATE_ALLOW_NETFS=1 with non-local "
                   "workspace fs (%s); mmap writeback exfiltration residual ACCEPTED "
                   "by operator\n",
                   fs_name.c_str());
    }
  }

  LatticeEngine engine;
  std::fprintf(stderr, "[mcp-dfa-gate] Policy: %.*s (SHA-256: %.*s)\n",
               static_cast<int>(mcp_lattice::policy::POLICY_NAME.size()),
               mcp_lattice::policy::POLICY_NAME.data(),
               static_cast<int>(mcp_lattice::policy::POLICY_SHA256.size()),
               mcp_lattice::policy::POLICY_SHA256.data());

  long timeout_secs = 600;
  if (const char* t = std::getenv("MCP_GATE_TIMEOUT_SECS")) {
    const long v = std::atol(t);
    if (v >= 0) timeout_secs = v;
  }
  if (timeout_secs > 0) {
    ::signal(SIGALRM, [](int) { ::_exit(42); });
  }

  const char* sec_env = std::getenv("MCP_GATE_SECCOMP");
  const bool enable_seccomp = (sec_env != nullptr && std::strcmp(sec_env, "1") == 0);

  const char* ll_env = std::getenv("MCP_GATE_LANDLOCK");
  const bool enable_landlock = (ll_env != nullptr && std::strcmp(ll_env, "1") == 0);
  if (enable_landlock) {
    const int abi = mcp_landlock::probe_abi_version();
    if (abi < 1) {
      std::fprintf(stderr,
                   "[mcp-dfa-gate] MCP_GATE_LANDLOCK=1 requested but Landlock LSM "
                   "is unavailable (errno=%d); refusing to start\n", errno);
      ::close(ws_fd);
      return 3;
    }
    std::fprintf(stderr, "[mcp-dfa-gate] LANDLOCK ACTIVE (ABI v%d; /proc excluded)\n", abi);
  }

  bool allow_partial_fence = false;
  if (const char* pf = std::getenv("MCP_GATE_ALLOW_PARTIAL_FENCE")) {
    allow_partial_fence = (std::strcmp(pf, "1") == 0);
  }
  if (enable_seccomp && allow_partial_fence) {
    std::fprintf(stderr,
                 "[mcp-dfa-gate] WARNING: MCP_GATE_ALLOW_PARTIAL_FENCE=1 -- "
                 "sweep failures will emit FENCE WARNING and RESUME the tree "
                 "with NO severance guarantee (mediated denies still active); "
                 "residual ACCEPTED by operator\n");
  }

  // v0.5: clearance masks are needed by both the supervisor start and the
  // quarantine-fence trigger below, so they are computed before the spawn.
  const auto net_rule = mcp_lattice::lookup_rule("http_fetch");
  const std::uint64_t net_clearance = net_rule ? net_rule->clearance_mask : 0ULL;
  const auto exec_rule = mcp_lattice::lookup_rule("bash_workspace");
  const std::uint64_t exec_clearance = exec_rule ? exec_rule->clearance_mask : 0ULL;
  // Conservative fence trigger: any taint bit not cleared for BOTH channels.
  const std::uint64_t combined_clearance = net_clearance | exec_clearance;

  std::atomic<std::uint64_t> shared_taint{0ULL};
  std::atomic<bool> shared_halted{false};
  mcp_seccomp::Supervisor supervisor;

  // v0.5.1: become a child subreaper BEFORE the spawn. The bit is inherited,
  // so the downstream root (and every descendant) is a subreaper too:
  // orphaned double-forked descendants reparent to the nearest live subreaper
  // INSIDE the tree instead of escaping to init, and anything orphaned above
  // a dead root lands on the sidecar itself. The fence's /proc ppid-walk
  // (root-anchored, plus the sidecar's own children) then sees every
  // fd-holding descendant. Fail closed: without it, daemonized children
  // would be invisible to the quarantine fence.
  if (enable_seccomp &&
      ::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
    std::fprintf(stderr,
                 "[mcp-dfa-gate] prctl(PR_SET_CHILD_SUBREAPER) failed: %s "
                 "(fence descendant discovery requires it); refusing to start\n",
                 std::strerror(errno));
    ::close(ws_fd);
    return 3;
  }

  Child child;
  if (!spawn_downstream(downstream, child, enable_seccomp, enable_landlock, safe_prefix)) {
    std::fprintf(stderr, "[mcp-dfa-gate] failed to spawn downstream server (seccomp=%d)\n",
                 enable_seccomp ? 1 : 0);
    ::close(ws_fd);
    return 3;
  }
  if (enable_seccomp) {
    if (!supervisor.start(child.seccomp_fd, &shared_taint, &shared_halted,
                          net_clearance, exec_clearance, child.pid, allow_partial_fence)) {
      std::fprintf(stderr, "[mcp-dfa-gate] failed to start seccomp supervisor\n");
      ::close(child.handoff_sock);
      ::close(ws_fd);
      return 3;
    }
    const char ack = 'K';
    const ssize_t wn = ::write(child.handoff_sock, &ack, 1);
    ::close(child.handoff_sock);
    child.handoff_sock = -1;
    if (wn != 1) {
      std::fprintf(stderr, "[mcp-dfa-gate] seccomp handoff ACK failed\n");
      ::close(ws_fd);
      return 3;
    }
    std::fprintf(stderr,
                 "[mcp-dfa-gate] SECCOMP_UNOTIFY ACTIVE (net=0x%016llx exec=0x%016llx)\n",
                 static_cast<unsigned long long>(net_clearance),
                 static_cast<unsigned long long>(exec_clearance));
  }

  LineReader client_in(STDIN_FILENO);
  LineReader child_out(child.from_child);
  std::string line;
  unsigned long seq = 0;

  while (client_in.next(line)) {
    ++seq;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;

    bool ascii_ok = true;
    for (const char c : line) {
      const auto u = static_cast<unsigned char>(c);
      if (u >= 0x80 || (u < 0x20 && c != '\t')) {
        ascii_ok = false;
        break;
      }
    }
    if (!ascii_ok) {
      emit(STDOUT_FILENO, make_error("null", kErrParse,
                                     "non-ASCII or control byte rejected (strict 7-bit transport)"));
      continue;
    }

    json::Node req;
    if (!json::parse(line, req, /*strict=*/true) ||
        req.type != json::Node::Type::kObj) {
      emit(STDOUT_FILENO, make_error("null", kErrParse, "invalid JSON-RPC message"));
      continue;
    }

    const json::Node* id_n = req.find("id");
    const bool is_notification = (id_n == nullptr);
    if (!is_notification &&
        id_n->type != json::Node::Type::kStr &&
        id_n->type != json::Node::Type::kNum &&
        id_n->type != json::Node::Type::kNull) {
      emit(STDOUT_FILENO, make_error("null", kErrInvalidRequest, "invalid JSON-RPC id type"));
      continue;
    }
    const std::string id_raw = is_notification ? std::string() : id_n->raw;

    const json::Node* method_n = req.find("method");
    if (method_n == nullptr || method_n->type != json::Node::Type::kStr) {
      emit(STDOUT_FILENO, make_error(id_raw, kErrInvalidRequest, "missing method"));
      continue;
    }
    const std::string& method = method_n->str;

    if (!method_allowed(method)) {
      std::fprintf(stderr,
                   "[mcp-dfa-gate] seq=%lu method=\"%s\" BLOCKED (fail-closed method policy)\n",
                   seq, method.c_str());
      if (!is_notification) {
        emit(STDOUT_FILENO, make_error(id_raw, kErrMethodBlocked,
                                       "method blocked by mcp-dfa-gate (fail-closed)"));
      }
      continue;
    }

    if (method == "tools/call") {
      const json::Node* params = req.find("params");
      const json::Node* name_n = (params != nullptr) ? params->find("name") : nullptr;
      const std::string tool =
          (name_n != nullptr && name_n->type == json::Node::Type::kStr)
              ? name_n->str : std::string();
      const json::Node* arguments = (params != nullptr) ? params->find("arguments") : nullptr;

      const Classification cls =
          classify_for_gate(tool, arguments, safe_prefix, ws_fd);

      // v0.6 (H4): argv-contract violations are refused before the lattice:
      // no state change, no forward, a clean -32602 with an actionable
      // message (a malformed frame is a client bug, not a policy event).
      // Content-level violations never reach this branch -- they classify as
      // UNKNOWN below and keep the v0.5 deny-and-absorb semantics.
      if (!cls.shape_ok) {
        std::fprintf(stderr,
                     "[mcp-dfa-gate] seq=%lu tool=\"%s\" REJECTED (argv contract violation)\n",
                     seq, tool.c_str());
        if (!is_notification) {
          emit(STDOUT_FILENO, make_error(id_raw, kErrInvalidParams, cls.shape_msg));
        }
        continue;
      }

      const bool is_sensitive = (cls.category == ToolCategory::SENSITIVE_READ);
      // Fail closed if classifier marked UNKNOWN (e.g. unvetted bash_workspace command)
      const std::string_view effective_tool =
          (cls.category == ToolCategory::UNKNOWN) ? std::string_view("") : std::string_view(tool);
      const auto st_before = engine.state();
      const auto r = engine.inspect_tool(effective_tool, is_sensitive);
      const auto st_after = engine.state();

      // v0.5 quarantine fence: when this call raises uncleared taint (or
      // halts the lattice) while the downstream tree may still hold live
      // sockets, sever every socket object BEFORE the new taint becomes
      // visible to the supervisor verdict loop. fence() is serialized
      // against all verdicts, so no CONTINUE can be issued after the raise;
      // write-family syscalls on severed sockets then fail with EPIPE
      // without per-write mediation.
      //
      // v0.5.1: the fence is the SOLE owner of the raise transition (it
      // stops, severs, and stores as one linearized unit); the sidecar
      // stores only benign transitions below. A false return means
      // descendant quiescence was unverifiable: terminate the downstream
      // tree and fail closed (exit 43) -- resuming an unverified process
      // would violate the linearization contract.
      const std::uint64_t new_uncleared =
          (st_after.taint & ~combined_clearance) &
          ~(st_before.taint & ~combined_clearance);
      const bool raised = enable_seccomp &&
                          ((new_uncleared != 0ULL) ||
                           (st_after.halted && !st_before.halted));
      if (raised) {
        if (!supervisor.fence(st_after.taint, st_after.halted)) {
          std::fprintf(stderr,
                       "[mcp-dfa-gate] FENCE FAILURE: terminating downstream "
                       "tree and exiting 43 (linearization unverified)\n");
          supervisor.kill_tree();
          ::_exit(43);
        }
      } else {
        shared_taint.store(st_after.taint, std::memory_order_release);
        shared_halted.store(st_after.halted, std::memory_order_release);
      }

      std::fprintf(stderr,
                   "[mcp-dfa-gate] seq=%lu tool=\"%s\" taint=0x%016llx allowed=%d\n",
                   seq, tool.c_str(),
                   static_cast<unsigned long long>(st_after.taint),
                   r.allowed ? 1 : 0);

      if (!r.allowed) {
        if (!is_notification) {
          emit(STDOUT_FILENO, make_error(id_raw, kErrPolicyDenied, r.reason));
        }
        continue;
      }
      if (!cls.canonical_ok) {
        if (!is_notification) {
          emit(STDOUT_FILENO,
               make_error(id_raw, kErrCanonicalization,
                          "path canonicalization failed; treated as sensitive; call refused"));
        }
        continue;
      }

      const std::string forwarded =
          build_forwarded_call(id_raw, is_notification, tool, cls);
      if (!is_notification && timeout_secs > 0) {
        ::alarm(static_cast<unsigned>(timeout_secs));
      }
      if (!emit(child.to_child, forwarded)) {
        std::fprintf(stderr, "[mcp-dfa-gate] downstream write failed\n");
        ::close(ws_fd);
        return 3;
      }
      if (!is_notification) {
        if (relay_matching(child_out, id_raw) != RelayResult::kOk) {
          std::fprintf(stderr, "[mcp-dfa-gate] downstream server lost\n");
          ::close(ws_fd);
          return 3;
        }
        if (timeout_secs > 0) ::alarm(0);
      }
      continue;
    }

    if (is_notification) {
      if (!emit(child.to_child, line)) {
        ::close(ws_fd);
        return 3;
      }
      continue;
    }
    if (timeout_secs > 0) ::alarm(static_cast<unsigned>(timeout_secs));
    if (!emit(child.to_child, line)) {
      ::close(ws_fd);
      return 3;
    }
    if (relay_matching(child_out, id_raw) != RelayResult::kOk) {
      std::fprintf(stderr, "[mcp-dfa-gate] downstream server lost\n");
      ::close(ws_fd);
      return 3;
    }
    if (timeout_secs > 0) ::alarm(0);
  }

  ::close(ws_fd);
  if (child.pid > 0) {
    ::kill(child.pid, SIGTERM);
    int status = 0;
    ::waitpid(child.pid, &status, 0);
  }
  return 0;
}
