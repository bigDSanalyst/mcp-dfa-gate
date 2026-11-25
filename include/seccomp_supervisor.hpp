#pragma once
// mcp-dfa-gate seccomp supervisor (v0.5)
//
// v0.5 hardening (audit C1/C2/C3/H3/H4 disposition):
//  * Filter now mediates the socket-creation family (socket, socketpair, accept,
//    accept4) in addition to egress (connect, sendto, sendmsg, sendmmsg) and
//    execution (execve, execveat). Mediated syscalls are checked against the live
//    taint mask; a tainted tree cannot create NEW sockets.
//  * Filter statically denies inspection/async surface with -EPERM (no notif cost):
//    ptrace, process_vm_readv/writev, kcmp, perf_event_open, open_by_handle_at,
//    bpf, userfaultfd, io_setup/io_submit, io_uring_setup/enter/register.
//  * Verifier visibility: prctl(PR_SET_DUMPABLE, 0) is statically denied
//    (argument-checked in BPF, no notif cost). A non-dumpable downstream
//    fails every sweep pidfd_getfd with EPERM (verified live), which would
//    silently disarm the fence; re-enabling visibility (argument 1) stays
//    allowed.
//  * Quarantine fence (C1/C2): when the sidecar raises uncleared taint (or halts),
//    Supervisor::fence() runs stop -> sweep -> shutdown(SHUT_RDWR) -> flip -> resume.
//    The sweep duplicates every fd of every tracked pid via pidfd_getfd and
//    shutdown()s every socket OBJECT, severing pre-existing/inherited/dup2-aliased
//    channels at the kernel socket layer. write/writev/sendfile/splice/tee/vmsplice
//    are deliberately NOT mediated: after the fence they face dead sockets (EPIPE)
//    or unconnected UDP (EDESTADDRREQ), and per-write USER_NOTIF traps would
//    reintroduce the seccomp_unotify(2) argument-race and hot-path cost.
//  * Verdict/fence mutual exclusion: every verdict (taint read -> NOTIF_SEND) and
//    the whole fence run under one mutex, so no CONTINUE can be issued after the
//    fence's atomic taint store. Syscalls blocked in-kernel inside USER_NOTIF when
//    the fence holds the lock are frozen pre-execution (no fd, no socket object)
//    and are answered with the post-fence taint.
//  * Sweep visibility: fds the sweep cannot duplicate for non-churn reasons
//    (EPERM across a user-namespace or ptrace boundary) are reported by a
//    loud FENCE WARNING: severance is not guaranteed in that mode; mediated
//    denies still hold.
//
// Linearization contract: a byte leaves the host only if its write syscall was
// completed (queued to the socket buffer) before the fence's shutdown() of that
// socket object; any write issued after the fence resumes fails with EPIPE.

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

// Expand to a (jump, USER_NOTIF) pair mediating syscall NR.
#define MCP_GATE_MEDIATE(NR) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(NR), 0, 1), \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)

// Expand to a (jump, -EPERM) pair statically denying syscall NR.
#define MCP_GATE_DENY(NR) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(NR), 0, 1), \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

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

      // ---- Static inspection / async-bypass denies (H3 + io_uring class) ----
#ifdef SYS_ptrace
      MCP_GATE_DENY(SYS_ptrace),
#endif
#ifdef SYS_process_vm_readv
      MCP_GATE_DENY(SYS_process_vm_readv),
#endif
#ifdef SYS_process_vm_writev
      MCP_GATE_DENY(SYS_process_vm_writev),
#endif
#ifdef SYS_kcmp
      MCP_GATE_DENY(SYS_kcmp),
#endif
#ifdef SYS_perf_event_open
      MCP_GATE_DENY(SYS_perf_event_open),
#endif
#ifdef SYS_open_by_handle_at
      MCP_GATE_DENY(SYS_open_by_handle_at),
#endif
#ifdef SYS_bpf
      MCP_GATE_DENY(SYS_bpf),
#endif
#ifdef SYS_userfaultfd
      MCP_GATE_DENY(SYS_userfaultfd),
#endif
#ifdef SYS_io_setup
      MCP_GATE_DENY(SYS_io_setup),
#endif
#ifdef SYS_io_submit
      MCP_GATE_DENY(SYS_io_submit),
#endif
#ifdef SYS_io_uring_setup
      MCP_GATE_DENY(SYS_io_uring_setup),
#endif
#ifdef SYS_io_uring_enter
      MCP_GATE_DENY(SYS_io_uring_enter),
#endif
#ifdef SYS_io_uring_register
      MCP_GATE_DENY(SYS_io_uring_register),
#endif

      // ---- Verifier visibility: the downstream may not hide from the fence ----
      // prctl(PR_SET_DUMPABLE, 0) makes every pidfd_getfd in the sweep fail
      // with EPERM (PTRACE_MODE_ATTACH), silently disarming severance
      // (verified live). Deny exactly that transition; re-enabling visibility
      // (argument 1) stays allowed. Pure-BPF argument snapshot: no USER_NOTIF
      // round-trip, no TOCTOU. The fall-through path reloads nr into A, so
      // the sections below still see the syscall number.
#ifdef SYS_prctl
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(SYS_prctl), 0, 6),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(PR_SET_DUMPABLE), 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#endif

      // ---- Socket creation family: no NEW sockets once tainted (C1/C2) ----
#ifdef SYS_socket
      MCP_GATE_MEDIATE(SYS_socket),
#endif
#ifdef SYS_socketpair
      MCP_GATE_MEDIATE(SYS_socketpair),
#endif
#ifdef SYS_accept
      MCP_GATE_MEDIATE(SYS_accept),
#endif
#ifdef SYS_accept4
      MCP_GATE_MEDIATE(SYS_accept4),
#endif

      // ---- Egress + execution mediation (v0.4 set) ----
      MCP_GATE_MEDIATE(SYS_connect),
      MCP_GATE_MEDIATE(SYS_sendto),
      MCP_GATE_MEDIATE(SYS_sendmsg),
#ifdef SYS_sendmmsg
      MCP_GATE_MEDIATE(SYS_sendmmsg),
#endif
      MCP_GATE_MEDIATE(SYS_execve),
#ifdef SYS_execveat
      MCP_GATE_MEDIATE(SYS_execveat),
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

#undef MCP_GATE_MEDIATE
#undef MCP_GATE_DENY

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
             std::atomic<std::uint64_t>* taint_mask,
             std::atomic<bool>* halted,
             std::uint64_t net_clearance_mask,
             std::uint64_t exec_clearance_mask,
             pid_t root_pid) {
    if (listener_fd < 0) return false;
    listener_fd_ = listener_fd;
    taint_mask_ = taint_mask;
    halted_ = halted;
    {
      std::lock_guard<std::mutex> lk(verdict_mutex_);
      register_pid_locked(root_pid);  // best effort; dead pid is harmless
    }
    stop_flag_.store(false, std::memory_order_relaxed);
    started_ = true;
    thread_ = std::thread([this, taint_mask, halted, net_clearance_mask, exec_clearance_mask]() {
      run_loop(taint_mask, halted, net_clearance_mask, exec_clearance_mask);
    });
    return true;
  }

  // Quarantine fence: the ONLY place taint may advance while sockets exist.
  // Serialized against verdicts by verdict_mutex_. Idempotent; call on every
  // raise (new uncleared taint bits or a fresh halt).
  //
  // Phase 1 (freeze): SIGSTOP tracked thread groups, then drain every pending
  //   notif with -EPERM. A drained syscall has NOT executed (it was blocked in
  //   USER_NOTIF), so draining guarantees no mediated socket creation can begin
  //   after this point; a CONTINUE issued before the fence has either finished
  //   (fd installed, enumerable) or the creating thread is still inside it --
  //   covered by the quiescing sweep.
  // Phase 2 (quiesce+sweep): repeatedly sweep every tracked fd table, shutting
  //   down every socket object, until a full pass severs nothing new. This
  //   closes the race where a CONTINUE'd socket/accept installs its fd between
  //   readdir() calls of a single pass (shutting the listener also aborts
  //   blocked accepts with EINVAL, so the sweep converges).
  // Phase 3 (linearize+resume): store the new mask, SIGCONT.
  void fence(std::uint64_t new_taint, bool new_halted) {
    if (!started_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(verdict_mutex_);
    const auto t0 = std::chrono::steady_clock::now();

    // Phase 1: freeze + drain pending verdicts.
    for (const auto& kv : pidfds_) {
      send_signal(kv.first, kv.second, SIGSTOP);
    }
    int drained = 0;
    bool all_stopped = false;
    for (int iter = 0; iter < 24 && !all_stopped; ++iter) {
      drained += drain_pending_eperm();
      all_stopped = true;
      for (const auto& kv : pidfds_) {
        if (!tgid_quiesced(kv.first)) {
          all_stopped = false;
          break;
        }
      }
      if (!all_stopped) ::usleep(5 * 1000);
    }

    // Phase 2: quiescing sweep.
    int scanned = 0;
    int severed = 0;
    int passes = 0;
    int unreachable_high_water = 0;
    for (int pass = 0; pass < 4; ++pass) {
      ++passes;
      int pass_severed = 0;
      int pass_unreachable = 0;
      for (const auto& kv : pidfds_) {
        const SweepResult r = sweep_sockets(kv.first, kv.second);
        scanned += r.duplicated;
        pass_severed += r.severed;
        pass_unreachable += r.unreachable;
      }
      severed += pass_severed;
      if (pass_unreachable > unreachable_high_water) {
        unreachable_high_water = pass_unreachable;
      }
      if (pass_severed == 0) break;  // fd tables quiesced: nothing new appeared
    }
    if (unreachable_high_water > 0) {
      // The sweep could not duplicate every fd. PR_SET_DUMPABLE(0) is denied
      // by the filter, but a user-namespace boundary (bwrap --unshare-pid) or
      // a credential change can still deny pidfd_getfd. Severance is NOT
      // guaranteed in this mode; every mediated syscall still denies.
      std::fprintf(stderr,
                   "[mcp-dfa-gate] FENCE WARNING: %d fd(s) unreachable for "
                   "pidfd_getfd; socket severance NOT guaranteed (userns or "
                   "ptrace boundary) -- mediated denies still active\n",
                   unreachable_high_water);
    }

    // Phase 3: linearization point.
    taint_mask_->store(new_taint, std::memory_order_release);
    halted_->store(new_halted, std::memory_order_release);

    for (const auto& kv : pidfds_) {
      send_signal(kv.first, kv.second, SIGCONT);
    }

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    std::fprintf(stderr,
                 "[mcp-dfa-gate] FENCE pids=%zu drained=%d passes=%d fds=%d "
                 "sockets_severed=%d taint=0x%016llx halted=%d (%lldms)\n",
                 pidfds_.size(), drained, passes, scanned, severed,
                 static_cast<unsigned long long>(new_taint), new_halted ? 1 : 0,
                 static_cast<long long>(ms));
  }

  // Respond -EPERM to every notif currently queued on the listener. Each
  // RECV is guarded by a zero-timeout poll: some kernels (e.g. 5.10) ignore
  // O_NONBLOCK for SECCOMP_IOCTL_NOTIF_RECV, and a blocking RECV on an empty
  // queue would deadlock the fence while it holds the verdict mutex. Every
  // drained syscall was frozen pre-execution inside USER_NOTIF, so answering
  // -EPERM is fail-closed and correct at a raise event.
  int drain_pending_eperm() noexcept {
    int drained = 0;
    for (;;) {
      struct pollfd pfd {};
      pfd.fd = listener_fd_;
      pfd.events = POLLIN;
      if (::poll(&pfd, 1, 0) <= 0) break;  // queue empty (or error)
      struct seccomp_notif req {};
      if (::ioctl(listener_fd_, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
        break;  // raced empty / EINTR / listener gone
      }
      struct seccomp_notif_resp resp {};
      resp.id = req.id;
      resp.error = -EPERM;
      resp.val = 0;
      resp.flags = 0;
      ::ioctl(listener_fd_, SECCOMP_IOCTL_NOTIF_SEND, &resp);
      ++drained;
    }
    return drained;
  }

  // True when every live task of the thread group is stopped ('T'/'t') or gone.
  static bool tgid_quiesced(pid_t tgid) noexcept {
    char dir[48];
    std::snprintf(dir, sizeof dir, "/proc/%d/task", static_cast<int>(tgid));
    DIR* d = ::opendir(dir);
    if (d == nullptr) return true;  // gone
    bool quiesced = true;
    struct dirent* e;
    while ((e = ::readdir(d)) != nullptr) {
      if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
      const int tid = std::atoi(e->d_name);
      if (tid <= 0) continue;
      // Reuse the per-tid state parser via /proc/<tid>/stat.
      if (!proc_state_stopped(tid)) {
        quiesced = false;
        break;
      }
    }
    ::closedir(d);
    return quiesced;
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
    std::lock_guard<std::mutex> lk(verdict_mutex_);
    for (auto& kv : pidfds_) {
      ::close(kv.second);
    }
    pidfds_.clear();
  }

 private:
  static void send_signal(pid_t pid, int pidfd, int sig) noexcept {
#if defined(SYS_pidfd_send_signal)
    if (::syscall(SYS_pidfd_send_signal, pidfd, sig, nullptr, 0U) == 0) return;
    if (errno == ESRCH) return;
#endif
    ::kill(pid, sig);  // fallback for kernels without pidfd_send_signal
  }

  static bool proc_state_stopped(pid_t tid) noexcept {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/stat", static_cast<int>(tid));
    FILE* f = std::fopen(path, "r");
    if (f == nullptr) return true;  // gone: cannot interfere
    char buf[512];
    const char* got = std::fgets(buf, sizeof buf, f);
    std::fclose(f);
    if (got == nullptr) return true;
    const char* rp = std::strrchr(buf, ')');
    if (rp == nullptr) return true;
    ++rp;
    while (*rp == ' ') ++rp;
    return (*rp == 'T' || *rp == 't');
  }

  // Sweep outcome for one tracked thread group. `unreachable` counts fds
  // the sweep could not duplicate for reasons other than EBADF (fd churn
  // while the table is not yet quiesced): e.g. EPERM when the target sits
  // across a user-namespace boundary (bwrap --unshare-pid) or is otherwise
  // not ptrace-accessible. Severance is not guaranteed for those fds; the
  // fence reports the condition loudly instead of failing silently.
  struct SweepResult {
    int duplicated;
    int severed;
    int unreachable;
  };

  static SweepResult sweep_sockets(pid_t pid, int pidfd) noexcept {
    SweepResult r{0, 0, 0};
    char dir[64];
    std::snprintf(dir, sizeof dir, "/proc/%d/fd", static_cast<int>(pid));
    DIR* d = ::opendir(dir);
    if (d == nullptr) {
      if (errno == EACCES || errno == EPERM) {
        r.unreachable = 1;  // cannot even enumerate the fd table
      }
      return r;  // ENOENT/ESRCH: process gone, nothing to sweep
    }
    struct dirent* e;
    while ((e = ::readdir(d)) != nullptr) {
      if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
      const int fdnum = std::atoi(e->d_name);
      const long dup = ::syscall(SYS_pidfd_getfd, pidfd, fdnum, 0U);
      if (dup < 0) {
        // EBADF: fd vanished between readdir() and getfd() (churn on a
        // not-yet-quiesced table; the next pass re-enumerates). Anything
        // else (EPERM-class) means the fd exists but we cannot reach it.
        if (errno != EBADF) ++r.unreachable;
        continue;
      }
      ++r.duplicated;
      struct stat st {};
      if (::fstat(static_cast<int>(dup), &st) == 0 && S_ISSOCK(st.st_mode)) {
        // Object-level kill: every alias in every process sees EPIPE/EOF.
        ::shutdown(static_cast<int>(dup), SHUT_RDWR);
        ++r.severed;
      }
      ::close(static_cast<int>(dup));
    }
    ::closedir(d);
    return r;
  }

  // Resolve a tid to its thread-group leader id via /proc/<tid>/status.
  // pidfd_open() rejects non-leader tids with EINVAL on some kernels (e.g.
  // 5.10), so the fence tracks processes, not threads. This is sufficient:
  // SIGSTOP via a leader pidfd is process-directed, and threads created with
  // CLONE_FILES (the normal case) share the leader's fd table, so the sweep
  // covers them. Threads with unshared fd tables only hold copies of objects
  // already present in a swept table, or sockets they cannot create (socket()
  // is mediated), so they are inert by construction.
  static pid_t tgid_of(pid_t tid) noexcept {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/status", static_cast<int>(tid));
    FILE* f = std::fopen(path, "r");
    if (f == nullptr) return -1;  // gone
    char buf[256];
    pid_t tgid = -1;
    while (std::fgets(buf, sizeof buf, f) != nullptr) {
      if (std::strncmp(buf, "Tgid:", 5) == 0) {
        tgid = static_cast<pid_t>(std::atoi(buf + 5));
        break;
      }
    }
    std::fclose(f);
    return tgid;
  }

  // Returns true when the thread group is tracked (or provably irrelevant).
  // False means "cannot guarantee tracking" and the caller must fail closed
  // with -EPERM.
  bool register_pid_locked(pid_t tid) {
    if (tid <= 0) return true;
    const pid_t tgid = tgid_of(tid);
    if (tgid < 0) return true;  // thread/process already gone
    if (pidfds_.find(tgid) != pidfds_.end()) return true;
    if (pidfds_.size() >= kMaxTrackedPids) return false;
    const long fd = ::syscall(SYS_pidfd_open, tgid, 0U);
    if (fd < 0) {
      if (errno == ESRCH) return true;  // died between status read and open
      std::fprintf(stderr, "[mcp-dfa-gate] pidfd_open(tgid=%d) failed errno=%d (%s)\n",
                   static_cast<int>(tgid), errno, std::strerror(errno));
      return false;  // cannot guarantee stop/sweep coverage: fail closed
    }
    pidfds_.emplace(tgid, static_cast<int>(fd));
    return true;
  }

  void run_loop(const std::atomic<std::uint64_t>* taint_mask,
                const std::atomic<bool>* halted,
                std::uint64_t net_clearance_mask,
                std::uint64_t exec_clearance_mask) {
    bool overflow_warned = false;
    while (!stop_flag_.load(std::memory_order_acquire)) {
      struct pollfd pfd {};
      pfd.fd = listener_fd_;
      pfd.events = POLLIN;
      const int prc = ::poll(&pfd, 1, 50);
      if (prc <= 0) continue;
      if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) break;

      struct seccomp_notif req {};
      if (::ioctl(listener_fd_, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
        if (errno == EINTR || errno == ENOENT || errno == EAGAIN) continue;
        break;
      }

      // Verdict critical section: mutually exclusive with fence(). A CONTINUE
      // can never be issued after the fence's taint store.
      std::lock_guard<std::mutex> lk(verdict_mutex_);
      const bool tracked = register_pid_locked(req.pid);

      const int nr = req.data.nr;
      bool is_exec = (nr == SYS_execve);
#ifdef SYS_execveat
      if (nr == SYS_execveat) is_exec = true;
#endif
      const std::uint64_t clearance = is_exec ? exec_clearance_mask : net_clearance_mask;

      const bool is_halted = halted->load(std::memory_order_acquire);
      const std::uint64_t taint = taint_mask->load(std::memory_order_acquire);
      const bool block = !tracked || is_halted || ((taint & ~clearance) != 0ULL);

      if (!tracked && !overflow_warned) {
        overflow_warned = true;
        std::fprintf(stderr,
                     "[mcp-dfa-gate] untracked pid %d fails closed (map size %zu, cap %zu)\n",
                     static_cast<int>(req.pid), pidfds_.size(), kMaxTrackedPids);
      }

      struct seccomp_notif_resp resp {};
      resp.id = req.id;
      if (block) {
        resp.error = -EPERM;
        resp.val = 0;
        resp.flags = 0;
        std::fprintf(stderr,
                     "[mcp-dfa-gate] SECCOMP_UNOTIFY DENIED pid=%d nr=%d (taint=0x%016llx halted=%d)\n",
                     static_cast<int>(req.pid), nr,
                     static_cast<unsigned long long>(taint), is_halted ? 1 : 0);
      } else {
        resp.error = 0;
        resp.val = 0;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
      }
      ::ioctl(listener_fd_, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
  }

  static constexpr std::size_t kMaxTrackedPids = 1024;

  int listener_fd_{-1};
  std::atomic<std::uint64_t>* taint_mask_{nullptr};
  std::atomic<bool>* halted_{nullptr};
  std::atomic<bool> stop_flag_{false};
  std::atomic<bool> started_{false};
  std::thread thread_;
  std::mutex verdict_mutex_;
  std::unordered_map<pid_t, int> pidfds_;
};

#else
inline bool child_install_and_handoff(int) noexcept { return false; }
inline int parent_fetch_listener_fd(int, pid_t) noexcept { return -1; }
class Supervisor {
 public:
  bool start(int, std::atomic<std::uint64_t>*, std::atomic<bool>*,
             std::uint64_t, std::uint64_t, pid_t) {
    return false;
  }
  void fence(std::uint64_t, bool) {}
  void stop() {}
};
#endif

}  // namespace mcp_seccomp
