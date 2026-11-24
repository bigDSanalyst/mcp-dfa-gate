#pragma once

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__linux__) && __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>) && __has_include(<linux/audit.h>)
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif

namespace mcp_seccomp {

#if defined(__linux__) && defined(SECCOMP_RET_USER_NOTIF) && defined(SECCOMP_IOCTL_NOTIF_RECV) && defined(SYS_pidfd_open) && defined(SYS_pidfd_getfd)

#if defined(__x86_64__)
inline constexpr std::uint32_t kExpectedArch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
inline constexpr std::uint32_t kExpectedArch = AUDIT_ARCH_AARCH64;
#else
#error "Unsupported architecture for seccomp BPF audit check"
#endif

// Child installs BPF filter, writes listener FD integer over unfiltered SYS_write,
// and blocks on SYS_read until parent duplicates the FD and starts the supervisor.
inline bool child_install_and_handoff(int sock) noexcept {
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return false;
  }
  struct sock_filter filter[] = {
      // Enforce native architecture to block 32-bit compat syscall number bypass
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kExpectedArch, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef SYS_io_uring_setup
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_setup, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
#endif
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#ifdef SYS_sendmmsg
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmmsg, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#endif
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#ifdef SYS_execveat
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#endif
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
      static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
      filter,
  };
  const long listener_fd = ::syscall(
      SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
  if (listener_fd < 0) {
    return false;
  }

  const int fd_num = static_cast<int>(listener_fd);
  if (::write(sock, &fd_num, sizeof(fd_num)) != static_cast<ssize_t>(sizeof(fd_num))) {
    ::close(fd_num);
    return false;
  }

  char ack = 0;
  const bool ok = (::read(sock, &ack, 1) == 1 && ack == 'K');
  ::close(fd_num);
  return ok;
}

// Parent reads child's listener FD number and duplicates it via pidfd_getfd (no sendmsg).
inline int parent_fetch_listener_fd(int sock, pid_t child_pid) noexcept {
  int child_fd = -1;
  if (::read(sock, &child_fd, sizeof(child_fd)) != static_cast<ssize_t>(sizeof(child_fd))) {
    return -1;
  }
  const long pidfd = ::syscall(SYS_pidfd_open, child_pid, 0U);
  if (pidfd < 0) {
    return -1;
  }
  const long dup_fd = ::syscall(SYS_pidfd_getfd, static_cast<int>(pidfd), child_fd, 0U);
  ::close(static_cast<int>(pidfd));
  return (dup_fd >= 0) ? static_cast<int>(dup_fd) : -1;
}

class Supervisor {
 public:
  Supervisor() = default;
  ~Supervisor() { stop(); }

  Supervisor(const Supervisor&) = delete;
  Supervisor& operator=(const Supervisor&) = delete;

  bool start(int listener_fd,
             const std::atomic<std::uint64_t>* taint_mask,
             const std::atomic<bool>* halted,
             std::uint64_t net_clearance_mask,
             std::uint64_t exec_clearance_mask) {
    if (listener_fd < 0) return false;
    listener_fd_ = listener_fd;
    stop_flag_.store(false, std::memory_order_relaxed);
    thread_ = std::thread([this, taint_mask, halted, net_clearance_mask, exec_clearance_mask]() {
      run_loop(taint_mask, halted, net_clearance_mask, exec_clearance_mask);
    });
    return true;
  }

  void stop() {
    stop_flag_.store(true, std::memory_order_release);
    if (thread_.joinable()) {
      thread_.join();
    }
    if (listener_fd_ >= 0) {
      ::close(listener_fd_);
      listener_fd_ = -1;
    }
  }

 private:
  void run_loop(const std::atomic<std::uint64_t>* taint_mask,
                const std::atomic<bool>* halted,
                std::uint64_t net_clearance_mask,
                std::uint64_t exec_clearance_mask) {
    while (!stop_flag_.load(std::memory_order_acquire)) {
      struct pollfd pfd {};
      pfd.fd = listener_fd_;
      pfd.events = POLLIN;
      const int prc = ::poll(&pfd, 1, 50);
      if (prc <= 0) continue;
      if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) break;

      struct seccomp_notif req {};
      if (::ioctl(listener_fd_, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
        if (errno == EINTR || errno == ENOENT) continue;
        break;
      }

      const int nr = req.data.nr;
      bool is_exec = (nr == SYS_execve);
#ifdef SYS_execveat
      if (nr == SYS_execveat) is_exec = true;
#endif
      const std::uint64_t clearance = is_exec ? exec_clearance_mask : net_clearance_mask;

      const bool is_halted = halted->load(std::memory_order_acquire);
      const std::uint64_t taint = taint_mask->load(std::memory_order_acquire);
      const bool block = is_halted || ((taint & ~clearance) != 0ULL);

      struct seccomp_notif_resp resp {};
      resp.id = req.id;
      if (block) {
        resp.error = -EPERM;
        resp.val = 0;
        resp.flags = 0;
        std::fprintf(stderr,
                     "[mcp-dfa-gate] SECCOMP_UNOTIFY DENIED nr=%d (taint=0x%016llx halted=%d)\n",
                     nr, static_cast<unsigned long long>(taint), is_halted ? 1 : 0);
      } else {
        resp.error = 0;
        resp.val = 0;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
      }
      ::ioctl(listener_fd_, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
  }

  int listener_fd_{-1};
  std::atomic<bool> stop_flag_{false};
  std::thread thread_;
};

#else
inline bool child_install_and_handoff(int) noexcept { return false; }
inline int parent_fetch_listener_fd(int, pid_t) noexcept { return -1; }
class Supervisor {
 public:
  bool start(int, const std::atomic<std::uint64_t>*, const std::atomic<bool>*,
             std::uint64_t, std::uint64_t) {
    return false;
  }
  void stop() {}
};
#endif

}  // namespace mcp_seccomp
