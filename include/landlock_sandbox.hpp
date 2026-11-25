#pragma once
// v0.6.2 (Issue #4): Linux 5.13+ Landlock LSM filesystem confinement.
//
// Landlock is an allowlist-only LSM (no deny rules). To block /proc/<pid>/mem,
// /proc/self/mem, and /proc/thread-self/mem, the child installs an ABI v1
// ruleset handling READ_FILE | WRITE_FILE | READ_DIR and allowlists only the
// workspace (SAFE_PREFIX) and standard runtime directories -- explicitly
// omitting /proc. Enabled via MCP_GATE_LANDLOCK=1; fails closed (exit 3) at
// startup if the kernel does not support Landlock.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#else
struct landlock_ruleset_attr {
  std::uint64_t handled_access_fs;
};
struct landlock_path_beneath_attr {
  std::uint64_t allowed_access;
  std::int32_t parent_fd;
} __attribute__((packed));
enum landlock_rule_type {
  LANDLOCK_RULE_PATH_BENEATH = 1,
};
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#endif
#endif

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

namespace mcp_landlock {

// Returns ABI version (>= 1) if Landlock is supported and enabled, or -1
// (with errno set: ENOSYS on kernels < 5.13, EOPNOTSUPP if disabled).
inline int probe_abi_version() noexcept {
  const long v = ::syscall(SYS_landlock_create_ruleset, nullptr,
                           static_cast<std::size_t>(0),
                           static_cast<std::uint32_t>(LANDLOCK_CREATE_RULESET_VERSION));
  return (v >= 1) ? static_cast<int>(v) : -1;
}

inline bool add_path_rule(int ruleset_fd, const char* path,
                          std::uint64_t access) noexcept {
  const int fd = ::open(path, O_PATH | O_CLOEXEC);
  if (fd < 0) {
    // Missing optional system dir (e.g., /lib64 on some distros) is benign.
    return errno == ENOENT;
  }
  struct landlock_path_beneath_attr attr {};
  attr.allowed_access = access;
  attr.parent_fd = fd;
  const long rc = ::syscall(SYS_landlock_add_rule, ruleset_fd,
                            LANDLOCK_RULE_PATH_BENEATH, &attr, 0U);
  ::close(fd);
  return rc == 0;
}

// Called in the forked downstream child right before execvp().
// Returns false on any error (caller must _exit(126) fail-closed).
inline bool child_apply_landlock(std::string_view safe_prefix) noexcept {
  constexpr std::uint64_t kReadOnly =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  constexpr std::uint64_t kReadWrite =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_READ_DIR;

  struct landlock_ruleset_attr attr {};
  attr.handled_access_fs = kReadWrite;

  const long rs_fd = ::syscall(SYS_landlock_create_ruleset, &attr,
                               sizeof attr, 0U);
  if (rs_fd < 0) return false;

  const int fd = static_cast<int>(rs_fd);
  bool ok = true;

  // Workspace root (guarantee null-termination safely from string_view).
  if (!safe_prefix.empty()) {
    std::string prefix_str(safe_prefix);
    ok = ok && add_path_rule(fd, prefix_str.c_str(), kReadOnly);
  }

  // Standard runtime directories (explicitly omitting /proc).
  const char* ro_dirs[] = {"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"};
  for (const char* d : ro_dirs) {
    if (!ok) break;
    ok = ok && add_path_rule(fd, d, kReadOnly);
  }
  
  const char* rw_dirs[] = {"/dev", "/tmp"};
  for (const char* d : rw_dirs) {
    if (!ok) break;
    ok = ok && add_path_rule(fd, d, kReadWrite);
  }

  if (!ok) {
    ::close(fd);
    return false;
  }
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    ::close(fd);
    return false;
  }
  const long rc = ::syscall(SYS_landlock_restrict_self, fd, 0U);
  ::close(fd);
  return rc == 0;
}

}  // namespace mcp_landlock

#else
namespace mcp_landlock {
inline int probe_abi_version() noexcept { return -1; }
inline bool child_apply_landlock(std::string_view) noexcept { return false; }
}  // namespace mcp_landlock
#endif
