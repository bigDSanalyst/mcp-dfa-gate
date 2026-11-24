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

#if defined(__linux__) && __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>)
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif

namespace mcp_seccomp {

#if defined(__linux__) && defined(SECCOMP_RET_USER_NOTIF) && defined(SECCOMP_IOCTL_NOTIF_RECV)

inline bool send_fd(int sock, int fd) noexcept {
  char dummy = 'F';
  struct iovec iov { &dummy, 1 };
  alignas(struct cmsghdr) char cbuf[CMSG_SPACE(sizeof(int))] = {};
  struct msghdr msg {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  std::memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

  return ::sendmsg(sock, &msg, 0) == 1;
}

inline int recv_fd(int sock) noexcept {
  char dummy = 0;
  struct iovec iov { &dummy, 1 };
  alignas(struct cmsghdr) char cbuf[CMSG_SPACE(sizeof(int))] = {};
  struct msghdr msg {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  if (::recvmsg(sock, &msg, 0) <= 0) return -1;
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
    return -1;
  }
  int fd = -1;
  std::memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
  return fd;
}

// Called in child process right before execvp().
// Installs SECCOMP_RET_USER_NOTIF on SYS_connect, sends listener FD to parent,
// and waits for 1-byte ACK so supervisor thread is active before execvp().
inline bool child_install_and_handoff(int sock) noexcept {
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return false;
  }
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
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
  const bool sent = send_fd(sock, static_cast<int>(listener_fd));
  ::close(static_cast<int>(listener_fd));
  if (!sent) return false;

  char ack = 0;
  return ::read(sock, &ack, 1) == 1 && ack == 'K';
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
             std::uint64_t net_clearance_mask) {
    if (listener_fd < 0) return false;
    listener_fd_ = listener_fd;
    stop_flag_.store(false, std::memory_order_relaxed);
    thread_ = std::thread([this, taint_mask, halted, net_clearance_mask]() {
      run_loop(taint_mask, halted, net_clearance_mask);
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
                std::uint64_t net_clearance_mask) {
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

      const bool is_halted = halted->load(std::memory_order_acquire);
      const std::uint64_t taint = taint_mask->load(std::memory_order_acquire);
      const bool block = is_halted || ((taint & ~net_clearance_mask) != 0ULL);

      struct seccomp_notif_resp resp {};
      resp.id = req.id;
      if (block) {
        resp.error = -EPERM;
        resp.val = 0;
        resp.flags = 0;
        std::fprintf(stderr,
                     "[mcp-dfa-gate] SECCOMP_UNOTIFY DENIED SYS_connect (taint=0x%016llx halted=%d)\n",
                     static_cast<unsigned long long>(taint), is_halted ? 1 : 0);
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
inline int recv_fd(int) noexcept { return -1; }
class Supervisor {
 public:
  bool start(int, const std::atomic<std::uint64_t>*, const std::atomic<bool>*, std::uint64_t) {
    return false;
  }
  void stop() {}
};
#endif

}  // namespace mcp_seccomp
