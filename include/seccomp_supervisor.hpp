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
// v0.5.1 fence correctness (external review disposition):
//  * Descendant discovery: at fence time the supervisor snapshots /proc and
//    follows ppid links from the downstream root (plus anything reparented
//    to the sidecar -- PR_SET_CHILD_SUBREAPER, set by the sidecar before the
//    spawn and inherited by the root, keeps orphaned double-forked
//    descendants inside the tree instead of escaping to init). Every
//    descendant is registered and SIGSTOPped before the sweep, so a silent
//    child that inherited a socket without ever calling a mediated syscall
//    can no longer escape the fence (v0.5.0 gap).
//  * Fail-closed quiescence: if any tracked thread group cannot be
//    VERIFIABLY stopped after bounded retries, the fence stores the taint
//    (mediated denies still hold), leaves the tree SIGSTOPped, and returns
//    false; the sidecar then terminates the session (exit 43). /proc read
//    errors count as unverified, never as success.
//  * Honest sweep accounting: shutdown() results are recorded and
//    classified by socket object identity (severed-new / already-severed /
//    inert ENOTCONN / unreachable / error); a quiesced pass is one that
//    severs nothing new with zero unreachables and zero errors.
//  * RECV under the verdict mutex (poll(0)-guarded): the supervisor's RECV
//    can no longer race the fence's drain, and the 5.10 blocking-RECV on an
//    empty queue cannot fire on any path.
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
#include <set>
#include <unordered_set>
#include <utility>
#include <vector>

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
             pid_t root_pid,
             bool allow_partial_fence = false) {
    if (listener_fd < 0) return false;
    listener_fd_ = listener_fd;
    taint_mask_ = taint_mask;
    halted_ = halted;
    {
      std::lock_guard<std::mutex> lk(verdict_mutex_);
      register_pid_locked(root_pid);  // best effort; dead pid is harmless
    }
    root_pid_ = root_pid;
    allow_partial_fence_ = allow_partial_fence;
    stop_flag_.store(false, std::memory_order_relaxed);
    try {
      thread_ = std::thread([this, taint_mask, halted, net_clearance_mask, exec_clearance_mask]() {
        run_loop(taint_mask, halted, net_clearance_mask, exec_clearance_mask);
      });
    } catch (...) {
      // v0.5.1: never appear started without a running supervisor thread.
      std::fprintf(stderr, "[mcp-dfa-gate] supervisor thread creation failed\n");
      ::close(listener_fd_);
      listener_fd_ = -1;
      return false;
    }
    started_.store(true, std::memory_order_release);
    return true;
  }

  // Quarantine fence: the ONLY place taint may advance while sockets exist.
  // Serialized against verdicts by verdict_mutex_. Idempotent; call on every
  // raise (new uncleared taint bits or a fresh halt).
  //
  // Returns false on FENCE FAILURE: quiescence of some fd-holding descendant
  // could not be VERIFIED, so the stop -> sever -> store -> resume
  // linearization contract cannot be honored. On failure the new taint is
  // still stored (every mediated syscall denies for every remaining
  // process) and the tree is left SIGSTOPped -- never resumed unverified.
  // The sidecar owns the policy and terminates the session.
  //
  // Phase 0 (discover+freeze fixpoint): snapshot /proc, walk ppid links from
  //   the downstream root and from the sidecar's own children (the sidecar
  //   is a child subreaper, so orphaned double-forked descendants reparent
  //   inside the tree instead of escaping to init), soft-register and SIGSTOP
  //   every descendant not yet tracked, drain pending notifs, and repeat
  //   until a round registers nobody new. Stopped processes cannot fork, so
  //   the fixpoint proves no fd-holding descendant is left running.
  // Phase 1 (quiescence confirmation): every tracked thread group must be
  //   verifiably stopped or gone (/proc read errors count as NOT stopped).
  //   Otherwise the fence fails closed.
  // Phase 2 (quiescing sweep): repeatedly sweep every tracked fd table,
  //   classifying shutdown() outcomes by socket object identity, until a
  //   full pass severs nothing new with zero unreachable fds and zero
  //   errors. Unreachable fds (pidfd_getfd failure of ANY class: credentials,
  //   dumpability, yama.ptrace_scope, user namespaces, LSM) or any sweep
  //   error / non-convergence is a FENCE FAILURE by default (v0.6.1
  //   strict): taint stored, tree left stopped, sidecar exits 43. Only an
  //   explicit MCP_GATE_ALLOW_PARTIAL_FENCE=1 downgrade emits a FENCE
  //   WARNING and resumes with NO severance guarantee (mediated denies
  //   still hold).
  // Phase 3 (linearize+resume): store the new mask (the linearization
  //   point), SIGCONT, report.
  bool fence(std::uint64_t new_taint, bool new_halted) {
    if (!started_.load(std::memory_order_acquire)) return true;
    std::lock_guard<std::mutex> lk(verdict_mutex_);
    const auto t0 = std::chrono::steady_clock::now();

    // Phase 0: discover + freeze to a fixpoint. A process forked by a
    // not-yet-stopped descendant after a scan is caught by the next round;
    // when a full round registers nobody new, every descendant is stopped
    // and no new one can appear.
    bool overflow = false;
    bool discovery_converged = false;
    bool discovery_degraded = false;
    int undeliverable_stops = 0;
    int rounds = 0;
    int drained = 0;
    for (int round = 0; round < 8; ++round) {
      ++rounds;
      const int fresh = discover_and_freeze_locked(
          &overflow, &discovery_degraded, &undeliverable_stops);
      drained += drain_pending_eperm();
      if (overflow) break;  // tracking cap exceeded: coverage impossible
      if (discovery_degraded) break;  // untrusted snapshot: fail closed below
      if (fresh == 0) {
        discovery_converged = true;
        break;
      }
    }

    // Phase 1: confirm every tracked thread group is verifiably stopped.
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

    if (!all_stopped || overflow || discovery_degraded ||
        !discovery_converged || undeliverable_stops > 0) {
      // FENCE FAILURE: fail closed. Resuming a process whose stop could not
      // be verified would violate the linearization contract (it may hold a
      // pre-existing socket and write to it during or after the sweep).
      taint_mask_->store(new_taint, std::memory_order_release);
      halted_->store(new_halted, std::memory_order_release);
      std::fprintf(stderr,
                   "[mcp-dfa-gate] FENCE FAILURE: descendant quiescence "
                   "unverified (stopped=%d converged=%d degraded=%d undeliverable=%d cap=%d); taint "
                   "stored, tree left stopped, terminating session\n",
                   all_stopped ? 1 : 0, discovery_converged ? 1 : 0,
                   discovery_degraded ? 1 : 0, undeliverable_stops,
                   overflow ? 1 : 0);
      return false;
    }

    // Phase 2: quiescing sweep with honest accounting. Every tracked task is
    // verified stopped, so fd tables are frozen: a quiesced pass verifies that every enumerated fd in the frozen
    // tables was classified with zero access-denied, zero errored, and no
    // newly severed S_ISSOCK object (not a blanket claim over non-sockets).
    std::set<std::pair<dev_t, ino_t>> severed_objects;  // v0.6.1: exact (st_dev, st_ino)
    int scanned = 0;
    int severed = 0;
    int already_severed = 0;
    int inert = 0;
    int unreachable_high_water = 0;
    int sweep_vanished = 0;
    int sweep_eperm = 0;
    int sweep_other = 0;
    int sweep_errors = 0;
    bool sweep_converged = false;
    int passes = 0;
    for (int pass = 0; pass < 4; ++pass) {
      ++passes;
      int pass_new = 0;
      int pass_unreachable = 0;
      int pass_vanished = 0;
      int pass_eperm = 0;
      int pass_other = 0;
      int pass_errors = 0;
      for (const auto& kv : pidfds_) {
        const SweepResult r =
            sweep_sockets(kv.first, kv.second, severed_objects);
        scanned += r.duplicated;
        pass_new += r.severed_new;
        already_severed += r.already_severed;
        inert += r.inert;
        pass_unreachable += r.unreachable;
        pass_errors += r.errors;
        pass_vanished += r.vanished;
        pass_eperm += r.eperm;
        pass_other += r.other_err;
      }
      severed += pass_new;
      if (pass_unreachable > unreachable_high_water) {
        unreachable_high_water = pass_unreachable;
      }
      sweep_errors += pass_errors;
      sweep_vanished += pass_vanished;
      sweep_eperm += pass_eperm;
      sweep_other += pass_other;
      if (pass_new == 0 && pass_unreachable == 0 && pass_errors == 0) {
        sweep_converged = true;  // fd tables quiesced: nothing new appeared
        break;
      }
    }
    if (unreachable_high_water > 0) {
      // The sweep could not duplicate every fd (user-namespace or ptrace
      // boundary, e.g. bwrap --unshare-pid, or a credential change).
      // Severance is NOT guaranteed in this mode; mediated denies still hold.
      std::fprintf(stderr,
                   "[mcp-dfa-gate] FENCE WARNING: %d fd(s) unreachable for "
                   "pidfd_getfd; socket severance NOT guaranteed (userns or "
                   "ptrace boundary) -- mediated denies still active "
                   "(vanished=%d eperm=%d other=%d)\n",
                   unreachable_high_water, sweep_vanished, sweep_eperm,
                   sweep_other);
    }
    if (sweep_errors > 0 || !sweep_converged) {
      std::fprintf(stderr,
                   "[mcp-dfa-gate] FENCE WARNING: sweep %s (errors=%d "
                   "passes=%d); severance accounting may be incomplete -- "
                   "mediated denies still active\n",
                   sweep_converged ? "reported errors" : "did not converge",
                   sweep_errors, passes);
    }

    // v0.6.1 (Issue #5): STRICT BY DEFAULT. Any unverified sweep
    // (unreachable fds, errors, or non-convergence) is a FENCE FAILURE:
    // store taint/halt, leave tree stopped, return false -> exit 43.
    if (unreachable_high_water > 0 || sweep_errors > 0 || !sweep_converged) {
      if (!allow_partial_fence_) {
        taint_mask_->store(new_taint, std::memory_order_release);
        halted_->store(new_halted, std::memory_order_release);
        std::fprintf(stderr,
                     "[mcp-dfa-gate] FENCE FAILURE (strict): sweep unverified "
                     "(unreachable=%d errors=%d converged=%d vanished=%d "
                     "eperm=%d other=%d); taint stored, tree left stopped, "
                     "terminating session\n",
                     unreachable_high_water, sweep_errors,
                     sweep_converged ? 1 : 0, sweep_vanished, sweep_eperm,
                     sweep_other);
        return false;
      }
      std::fprintf(stderr,
                   "[mcp-dfa-gate] FENCE RESIDUAL ACCEPTED: "
                   "MCP_GATE_ALLOW_PARTIAL_FENCE=1 -- resuming tree with NO "
                   "severance guarantee (mediated denies still active)\n");
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
                 "[mcp-dfa-gate] FENCE pids=%zu rounds=%d drained=%d "
                 "passes=%d fds=%d severed=%d already=%d inert=%d "
                 "(taint=0x%016llx halted=%d %lldms)\n",
                 pidfds_.size(), rounds, drained, passes, scanned, severed,
                 already_severed, inert,
                 static_cast<unsigned long long>(new_taint),
                 new_halted ? 1 : 0, static_cast<long long>(ms));
    return true;
  }

  // FENCE FAILURE path: best-effort SIGKILL of every tracked process. The
  // sidecar calls this and exits immediately after fence() returns false.
  void kill_tree() noexcept {
    if (!started_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(verdict_mutex_);
    for (const auto& kv : pidfds_) {
      send_signal(kv.first, kv.second, SIGKILL);
    }
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

  // True when every live task of the thread group is stopped ('T'/'t'),
  // dead ('Z'/'X'), or gone. Unreadable state is NOT quiesced: the caller
  // must treat it as unverified (fail closed).
  static bool tgid_quiesced(pid_t tgid) noexcept {
    char dir[48];
    std::snprintf(dir, sizeof dir, "/proc/%d/task", static_cast<int>(tgid));
    DIR* d = ::opendir(dir);
    if (d == nullptr) {
      return errno == ENOENT;  // gone = quiesced; unreadable = unverified
    }
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
  // True when the signal was delivered (or the target is already gone, which
  // cannot interfere with the fence). False = undeliverable: the caller's
  // stop/quiesce verification must treat the target as unverified.
  static bool send_signal(pid_t pid, int pidfd, int sig) noexcept {
#if defined(SYS_pidfd_send_signal)
    if (pidfd >= 0) {
      if (::syscall(SYS_pidfd_send_signal, pidfd, sig, nullptr, 0U) == 0) {
        return true;
      }
      if (errno == ESRCH) return true;  // gone: cannot interfere
      const int handle_err = errno;
      if (handle_err != ENOSYS) {
        std::fprintf(stderr,
                     "[mcp-dfa-gate] pidfd_send_signal(pid=%d sig=%d) failed "
                     "errno=%d; refusing kill() fallback\n",
                     static_cast<int>(pid), sig, handle_err);
        return false;
      }
    }
#endif
    if (::kill(pid, sig) == 0) return true;
    return errno == ESRCH;  // gone: cannot interfere
  }

  static bool proc_state_stopped(pid_t tid) noexcept {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/stat", static_cast<int>(tid));
    FILE* f = std::fopen(path, "r");
    if (f == nullptr) {
      return errno == ENOENT || errno == ESRCH;  // gone; unreadable = unverified
    }
    char buf[512];
    errno = 0;
    const char* got = std::fgets(buf, sizeof buf, f);
    const int saved_errno = errno;
    std::fclose(f);
    if (got == nullptr) {
      return saved_errno == ENOENT || saved_errno == ESRCH;
    }
    const char* rp = std::strrchr(buf, ')');
    if (rp == nullptr) return false;  // malformed/truncated = unverified, fail closed
    ++rp;
    while (*rp == ' ') ++rp;
    // 'T'/'t' = stopped. 'Z' (zombie) / 'X' (dead) hold no fds and cannot
    // interfere; anything else (R, S, D, ...) is not verified-stopped.
    return (*rp == 'T' || *rp == 't' || *rp == 'Z' || *rp == 'X');
  }

  // Sweep outcome for one tracked thread group (one pass):
  //  severed_new:     shutdown() == 0 on a socket object not seen severed
  //                   before in this fence (object identity via (dev,ino)).
  //  already_severed: shutdown() == 0 on an object severed in an earlier
  //                   pass (idempotent re-sweep of a frozen table).
  //  inert:           shutdown() == ENOTCONN: an unconnected socket cannot
  //                   transmit -- transmission requires connect()/sendto(),
  //                   both mediated -- so it is left alone deliberately.
  //  unreachable:     the fd exists but pidfd_getfd could not duplicate it
  //                   (EPERM-class: user-namespace / ptrace boundary), or
  //                   the fd table itself is unenumerable.
  //  errors:          shutdown() failed for an unexpected reason.
  struct SweepResult {
    int duplicated = 0;
    int severed_new = 0;
    int already_severed = 0;
    int inert = 0;
    int unreachable = 0;  // total access/enumeration failures
    int errors = 0;       // unexpected shutdown() failures
    int vanished = 0;     // EBADF/ESRCH
    int eperm = 0;        // EPERM/EACCES
    int other_err = 0;    // any other errno
  };

  // Stable identity of the underlying kernel object (socket inode); two
  // aliased fds (dup2/fork/SCM_RIGHTS) map to the same key, so a re-swept
  // object is classified "already severed" instead of double-counted.
  // v0.6.1: exact (st_dev, st_ino) pair in std::set replaces lossy scalar hash.

  static SweepResult sweep_sockets(
      pid_t pid, int pidfd,
      std::set<std::pair<dev_t, ino_t>>& severed) noexcept {
    SweepResult r{};
    char dir[64];
    std::snprintf(dir, sizeof dir, "/proc/%d/fd", static_cast<int>(pid));
    DIR* d = ::opendir(dir);
    if (d == nullptr) {
      if (errno == ENOENT) return r;  // process gone mid-fence
      ++r.unreachable;
      if (errno == EACCES || errno == EPERM) {
        ++r.eperm;
      } else {
        ++r.other_err;
      }
      return r;
    }
    struct dirent* e;
    while ((e = ::readdir(d)) != nullptr) {
      if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
      const int fdnum = std::atoi(e->d_name);
      if (pidfd < 0) {
        ++r.unreachable;  // no pidfd: cannot duplicate anything (warn class)
        continue;
      }
      const long dup = ::syscall(SYS_pidfd_getfd, pidfd, fdnum, 0U);
      if (dup < 0) {
        const int gerr = errno;
        ++r.unreachable;
        if (gerr == EBADF || gerr == ESRCH) {
          ++r.vanished;
        } else if (gerr == EPERM || gerr == EACCES) {
          ++r.eperm;
        } else {
          ++r.other_err;
        }
        continue;
      }
      ++r.duplicated;
      struct stat st {};
      if (::fstat(static_cast<int>(dup), &st) == 0 && S_ISSOCK(st.st_mode)) {
        // Object-level kill: every alias in every process sees EPIPE/EOF.
        if (::shutdown(static_cast<int>(dup), SHUT_RDWR) == 0) {
          if (severed.emplace(st.st_dev, st.st_ino).second) {
            ++r.severed_new;
          } else {
            ++r.already_severed;
          }
        } else if (errno == ENOTCONN) {
          ++r.inert;
        } else {
          ++r.errors;
        }
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

  // Target-scoped descendant discovery (v0.6.1): walk
  // /proc/<pid>/task/<tid>/children recursively from root_pid_ and getpid()
  // (PR_SET_CHILD_SUBREAPER keeps orphans reparented inside the tree). Only
  // touches our own process tree, never unrelated PIDs on shared/hidepid hosts.
  // Falls back to global /proc ppid-walk only if children is unavailable
  // (ENOENT), ignoring EACCES/EPERM on foreign UIDs.
  static bool read_direct_children(pid_t pid, std::vector<pid_t>& out,
                                   bool* children_supported,
                                   bool* degraded) noexcept {
    char tdir[48];
    std::snprintf(tdir, sizeof tdir, "/proc/%d/task", static_cast<int>(pid));
    DIR* d = ::opendir(tdir);
    if (d == nullptr) {
      if (errno != ENOENT) *degraded = true;
      return false;
    }
    struct dirent* e;
    while ((e = ::readdir(d)) != nullptr) {
      if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
      const int tid = std::atoi(e->d_name);
      if (tid <= 0) continue;
      char cpath[80];
      std::snprintf(cpath, sizeof cpath, "/proc/%d/task/%d/children",
                    static_cast<int>(pid), tid);
      FILE* f = std::fopen(cpath, "r");
      if (f == nullptr) {
        if (errno == ENOENT) {
          char spath[80];
          std::snprintf(spath, sizeof spath, "/proc/%d/task/%d/stat",
                        static_cast<int>(pid), tid);
          if (::access(spath, F_OK) == 0) {
            *children_supported = false;
            ::closedir(d);
            return false;
          }
          continue;
        }
        *degraded = true;
        continue;
      }
      int cpid = 0;
      while (std::fscanf(f, "%d", &cpid) == 1) {
        if (cpid > 0) out.push_back(static_cast<pid_t>(cpid));
      }
      std::fclose(f);
    }
    ::closedir(d);
    return true;
  }

  int discover_and_freeze_locked(bool* overflow, bool* discovery_degraded,
                                 int* undeliverable_stops) {
    const pid_t me = ::getpid();
    std::vector<pid_t> stack;
    std::unordered_set<pid_t> closure;
    bool children_supported = true;
    bool local_degraded = false;

    if (root_pid_ > 0) {
      closure.insert(root_pid_);
      stack.push_back(root_pid_);
    }
    {
      std::vector<pid_t> my_kids;
      read_direct_children(me, my_kids, &children_supported, &local_degraded);
      for (const pid_t c : my_kids) {
        if (c != me && closure.insert(c).second) stack.push_back(c);
      }
    }
    while (children_supported && !stack.empty()) {
      const pid_t p = stack.back();
      stack.pop_back();
      std::vector<pid_t> kids;
      read_direct_children(p, kids, &children_supported, &local_degraded);
      for (const pid_t c : kids) {
        if (c != me && closure.insert(c).second) stack.push_back(c);
      }
    }

    if (!children_supported) {
      closure.clear();
      stack.clear();
      local_degraded = false;
      std::unordered_map<pid_t, pid_t> ppid_of;
      if (!scan_proc_ppids(ppid_of, &local_degraded)) {
        local_degraded = true;
      } else {
        std::unordered_map<pid_t, std::vector<pid_t>> kids;
        for (const auto& kv : ppid_of) kids[kv.second].push_back(kv.first);
        if (root_pid_ > 0 && ppid_of.count(root_pid_) != 0) {
          closure.insert(root_pid_);
          stack.push_back(root_pid_);
        }
        for (const pid_t c : kids[me]) {
          if (c != me && closure.insert(c).second) stack.push_back(c);
        }
        while (!stack.empty()) {
          const pid_t p = stack.back();
          stack.pop_back();
          for (const pid_t c : kids[p]) {
            if (closure.insert(c).second) stack.push_back(c);
          }
        }
      }
    }

    if (local_degraded && discovery_degraded != nullptr) {
      *discovery_degraded = true;
    }

    closure.erase(me);  // never stop or sweep ourselves
    int fresh = 0;
    for (const pid_t p : closure) {
      if (pidfds_.find(p) != pidfds_.end()) continue;
      if (pidfds_.size() >= kMaxTrackedPids) {
        *overflow = true;
        break;
      }
      const long fd = ::syscall(SYS_pidfd_open, p, 0U);
      if (fd < 0 && errno != ESRCH) {
        std::fprintf(stderr,
                     "[mcp-dfa-gate] FENCE WARNING: pidfd_open(pid=%d) "
                     "failed errno=%d; sweep cannot reach this fd table\n",
                     static_cast<int>(p), errno);
      }
      pidfds_.emplace(p, fd >= 0 ? static_cast<int>(fd) : -1);
      ++fresh;
    }
    for (const auto& kv : pidfds_) {
      if (!send_signal(kv.first, kv.second, SIGSTOP) &&
          undeliverable_stops != nullptr) {
        ++*undeliverable_stops;
      }
    }
    return fresh;
  }

  static bool scan_proc_ppids(std::unordered_map<pid_t, pid_t>& out,
                              bool* degraded) noexcept {
    DIR* d = ::opendir("/proc");
    if (d == nullptr) return false;
    const uid_t my_uid = ::geteuid();
    struct dirent* e;
    while ((e = ::readdir(d)) != nullptr) {
      if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
      const pid_t pid = static_cast<pid_t>(std::atoi(e->d_name));
      if (pid <= 0) continue;
      pid_t tgid = -1;
      pid_t ppid = -1;
      int rerr = 0;
      if (read_tgid_ppid(pid, &tgid, &ppid, &rerr)) {
        if (tgid == pid && ppid >= 0) out.emplace(pid, ppid);
      } else if (rerr != ENOENT) {
        char pdir[32];
        std::snprintf(pdir, sizeof pdir, "/proc/%d", static_cast<int>(pid));
        struct stat st {};
        if ((rerr == EACCES || rerr == EPERM) &&
            ::stat(pdir, &st) == 0 && st.st_uid != my_uid) {
          continue;
        }
        *degraded = true;
      }
    }
    ::closedir(d);
    return true;
  }

  static bool read_tgid_ppid(pid_t pid, pid_t* tgid, pid_t* ppid,
                             int* err) noexcept {
    char path[48];
    std::snprintf(path, sizeof path, "/proc/%d/status", static_cast<int>(pid));
    *tgid = -1;
    *ppid = -1;
    *err = 0;
    FILE* f = std::fopen(path, "r");
    if (f == nullptr) {
      *err = errno;
      return false;
    }
    char buf[256];
    while (std::fgets(buf, sizeof buf, f) != nullptr) {
      if (std::strncmp(buf, "Tgid:", 5) == 0) {
        *tgid = static_cast<pid_t>(std::atoi(buf + 5));
      } else if (std::strncmp(buf, "PPid:", 5) == 0) {
        *ppid = static_cast<pid_t>(std::atoi(buf + 5));
      }
      if (*tgid > 0 && *ppid >= 0) break;
    }
    std::fclose(f);
    if (*tgid <= 0 || *ppid < 0) {
      *err = EIO;
      return false;
    }
    return true;
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
      const int prc = ::poll(&pfd, 1, 50);  // idle wait OUTSIDE the mutex
      if (prc <= 0) continue;
      if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) break;

      // Verdict critical section (v0.5.1: RECV included): mutually exclusive
      // with fence(), so a fence drain can never race our RECV, and no
      // CONTINUE can be issued after the fence's taint store. The poll(0)
      // re-check under the mutex proves the queue is non-empty when we
      // RECV -- kernels that ignore O_NONBLOCK on NOTIF_RECV (e.g. 5.10)
      // cannot block us here, and the fence is never starved by an idle
      // supervisor thread.
      std::lock_guard<std::mutex> lk(verdict_mutex_);
      struct pollfd pfd2 {};
      pfd2.fd = listener_fd_;
      pfd2.events = POLLIN;
      if (::poll(&pfd2, 1, 0) <= 0) continue;  // a fence drained it
      struct seccomp_notif req {};
      if (::ioctl(listener_fd_, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
        if (errno == EINTR || errno == ENOENT || errno == EAGAIN) continue;
        break;
      }
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
  pid_t root_pid_{-1};
  bool allow_partial_fence_{false};
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
             std::uint64_t, std::uint64_t, pid_t, bool = false) {
    return false;
  }
  bool fence(std::uint64_t, bool) { return true; }
  void kill_tree() noexcept {}
  void stop() {}
};
#endif

}  // namespace mcp_seccomp
