# mcp-dfa-gate (v0.5.0)

Zero-dependency C++20 `stdio` JSON-RPC security sidecar for Model Context Protocol (MCP) agents, backed by a 64-bit bitwise taint-lattice engine, a JSON policy-to-proof compiler, a Lean 4 universal Non-Interference proof, and a Linux `SECCOMP_RET_USER_NOTIF` quarantine fence.

## Requirements

* **Linux 5.9+** (verified on Linux 5.10 locally and Linux 6.x on GitHub Actions CI)
* C++20 compiler (`g++` / `clang++`) and Python 3.10+ (for policy compilation and tests)
* Optional: Lean 4 (for re-checking `lean/lattice_proof.lean`)

## Key Properties

* **64-bit Taint-Lattice Engine (`include/lattice_engine.hpp`):** Models up to 64 independent taint domains (2^64 effective DFA states) via branchless bitwise transitions (`1.99 ns` avg over 10,000,000 calls). Non-copyable, non-movable, non-resettable, lvalue-ref-qualified (`&`).
* **Policy-to-Proof Compiler (`tools/policy_compiler.py`):** Compiles a canonical JSON policy (`policies/enterprise_example.json`) into both `include/generated_policy.hpp` (with a SHA-256 commitment) and `lean/generated_policy_cert.lean`.
* **Lean 4 Universal Non-Interference (`lean/lattice_proof.lean`):** Kernel-checked on Lean 4 (no Mathlib, no `sorry`, no `native_decide`; standard `BitVec` axioms `[propext, Classical.choice, Quot.sound]`). Proves by induction that once any taint bit `i` is set, no arbitrary-length trace containing a tool lacking clearance for `i` can succeed.
* **Egress Mediation & Quarantine Fence (`include/seccomp_supervisor.hpp`):** When `MCP_GATE_SECCOMP=1` is set, installs an `AUDIT_ARCH`-guarded `SECCOMP_RET_USER_NOTIF` BPF filter on the downstream process (transferred via `pidfd_open` / `pidfd_getfd`).
  * **Two-phase quarantine fence:** On taint raise or lattice halt, the supervisor serializes under `verdict_mutex_`, `SIGSTOP`s tracked thread groups, drains pending notifications with `-EPERM`, sweeps every tracked process's FDs via `pidfd_getfd` and `shutdown(SHUT_RDWR)`s the underlying socket objects until quiescent, then linearizes the taint state and resumes. Pre-existing, `dup2`-aliased, forked, `socketpair`, and `SCM_RIGHTS` sockets are severed at the kernel object layer -- no per-write interception.
  * **Mediated syscalls (`USER_NOTIF`):** Socket creation (`socket`, `socketpair`, `accept`, `accept4`), egress (`connect`, `sendto`, `sendmsg`, `sendmmsg`), and execution (`execve`, `execveat`). `accept`/`accept4` are denied outright while tainted, so a surviving pre-taint listener cannot yield a usable connection.
  * **Static `-EPERM` denies (zero notif cost):** `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `perf_event_open`, `open_by_handle_at`, `bpf`, `userfaultfd`, `io_setup`, `io_submit`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, and argument-checked `prctl(PR_SET_DUMPABLE, 0)` (prevents a downstream from disarming the fence's own FD inspection).
* **Local-Filesystem Pin (`src/mcp_sidecar.cpp`):** At startup, the sidecar checks the workspace root with `statfs(2)`. The workspace must be on a local filesystem (`ext2/3/4`, `xfs`, `btrfs`, `f2fs`, `tmpfs`, `ramfs`, `overlayfs`). Network and pseudo filesystems (`NFS`, `CIFS/SMB`, `SMB2`, `FUSE`, `9P`, `CEPH`, `AFS`, `NCP`, `procfs`, or unknown) cause startup to fail closed with **exit 2**, because kernel `mmap` writeback bypasses syscall mediation. Override with `MCP_GATE_ALLOW_NETFS=1` only if you explicitly accept that residual.
* **Hardened C++20 Sidecar (`src/mcp_sidecar.cpp`):**
  * Strict 7-bit ASCII transport, 1 MiB line cap, duplicate JSON key rejection, and JSON-RPC `id` type validation.
  * Fail-closed method allowlist (`initialize`, `initialized`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`).
  * Rebuilds `tools/call` frames from whitelisted fields; raw client JSON is never forwarded.
  * Linux `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` + `fstat(S_ISREG)` canonicalization (with `O_NOFOLLOW` fallback).
  * Vetted read-only command allowlist for `bash_workspace` (blocks metacharacters, flag-embedded paths, dotfiles, sensitive suffixes, and symlinks).

## Quick Start & Testing

```bash
make policy        # Compile policies/enterprise_example.json -> C++20 + Lean 4
make build         # Compile mcp-dfa-gate (-std=c++20 -O2 -Wall -Wextra -Wpedantic -pthread)
make test          # Run 24 hostile integration tests (tests/test_sidecar.py) -> 24/24
make test-seccomp  # Run 20 live-kernel red-team tests (tests/test_seccomp.py) -> 20/20
make verify        # Check Lean 4 universal Non-Interference proof
```

## Usage

Standard sidecar mode:

```bash
./mcp-dfa-gate /workspace/public/ -- python3 -m your_mcp_server
```

With Linux kernel `SECCOMP_RET_USER_NOTIF` enforcement:

```bash
MCP_GATE_SECCOMP=1 ./mcp-dfa-gate /workspace/public/ -- python3 -m your_mcp_server
```

For production OS confinement (read-only workspace bind mount + `cwd` lock):

```bash
MCP_GATE_SECCOMP=1 ./scripts/run_confined.sh /workspace/public -- python3 -m your_mcp_server
```

## Upgrade Notes (v0.4 -> v0.5.0)

* **Non-local workspaces now refuse to start (exit 2):** Workspaces on NFS, CIFS/SMB, FUSE, 9P, Ceph, AFS, procfs, or unknown filesystems fail closed at startup. Set `MCP_GATE_ALLOW_NETFS=1` to override.
* **`accept` / `accept4` are denied post-taint:** Pre-taint listening sockets cannot accept new connections once taint is raised.
* **`prctl(PR_SET_DUMPABLE, 0)` is statically denied (`EPERM`):** Tools that call `prctl(PR_SET_DUMPABLE, 0)` deliberately for core-dump hygiene will receive `EPERM` (re-enabling dumpability with argument `1` remains allowed).

## Known Residuals

See `SECURITY.md` for the full threat model and trust boundaries. Key residuals tracked for `v0.6`:

* **`bash_workspace` shell parsing (H4):** Replacement with typed argv-array primitives is scheduled for `v0.6`.
* **Confined (`bwrap`) fence boundary:** The FD sweep is verified in direct sidecar mode only. Under `bwrap --unshare-pid` with an unprivileged user namespace (or `kernel.yama.ptrace_scope >= 2`), `pidfd_getfd` may fail with `EPERM`; the fence emits a loud `FENCE WARNING` and mediated syscalls still deny, but pre-taint sockets may survive (`--unshare-net` mitigates; `bwrap`-mode testing and a sweep privilege model are tracked for `v0.6`).
* **Landlock `/proc/<pid>/mem` hardening:** Scheduled for `v0.6` (Linux 5.13+).

## License

Copyright (c) 2026 Nicholas Clifford Maino III.

`mcp-dfa-gate` is dual-licensed under the **GNU Affero General Public License v3.0 (AGPLv3)** (see `LICENSE`) and a **Commercial License** (see `COMMERCIAL.md`) for proprietary production deployments.
