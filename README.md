# mcp-dfa-gate (v0.6.2)

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
  * **Quarantine fence with descendant discovery (v0.5.1):** On taint raise or lattice halt, the supervisor serializes under `verdict_mutex_`, snapshots `/proc` and follows ppid links from the downstream root and the sidecar's own children (the sidecar is a `PR_SET_CHILD_SUBREAPER` and the bit is inherited, so orphaned double-forked daemons stay inside the tree), `SIGSTOP`s and soft-registers every descendant to a fixpoint, drains pending notifications with `-EPERM`, verifies every thread group is stopped, sweeps every fd via `pidfd_getfd` and `shutdown(SHUT_RDWR)`s the underlying socket objects (accounting classified by socket object identity) until a quiesced pass, then linearizes the taint state and resumes. Pre-existing, `dup2`-aliased, forked, `socketpair`, and `SCM_RIGHTS` sockets — including one held only by a silent child that never called a mediated syscall — are severed at the kernel object layer, no per-write interception. If quiescence cannot be verified, the fence fails closed: the taint is still stored, the tree is left stopped and terminated, and the sidecar exits **43**.
  * **Mediated syscalls (`USER_NOTIF`):** Socket creation (`socket`, `socketpair`, `accept`, `accept4`), egress (`connect`, `sendto`, `sendmsg`, `sendmmsg`), and execution (`execve`, `execveat`). `accept`/`accept4` are denied outright while tainted, so a surviving pre-taint listener cannot yield a usable connection.
  * **Static `-EPERM` denies (zero notif cost):** `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `perf_event_open`, `open_by_handle_at`, `bpf`, `userfaultfd`, `io_setup`, `io_submit`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, and argument-checked `prctl(PR_SET_DUMPABLE, 0)` (prevents a downstream from disarming the fence's own FD inspection).
* **Local-Filesystem Pin (`src/mcp_sidecar.cpp`):** At startup, the sidecar checks the workspace root with `statfs(2)`. The workspace must be on a local filesystem (`ext2/3/4`, `xfs`, `btrfs`, `f2fs`, `tmpfs`, `ramfs`, `overlayfs`). Network and pseudo filesystems (`NFS`, `CIFS/SMB`, `SMB2`, `FUSE`, `9P`, `CEPH`, `AFS`, `NCP`, `procfs`, or unknown) cause startup to fail closed with **exit 2**, because kernel `mmap` writeback bypasses syscall mediation. Override with `MCP_GATE_ALLOW_NETFS=1` only if you explicitly accept that residual.
* **Hardened C++20 Sidecar (`src/mcp_sidecar.cpp`):**
  * Strict 7-bit ASCII transport, 1 MiB line cap, duplicate JSON key rejection, and JSON-RPC `id` type validation.
  * Fail-closed method allowlist (`initialize`, `initialized`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`).
  * Rebuilds `tools/call` frames from whitelisted fields; raw client JSON is never forwarded.
  * Linux `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` + `fstat(S_ISREG)` canonicalization (with `O_NOFOLLOW` fallback).
  * Vetted typed-argv contract for `bash_workspace` (v0.6, closes H4): arguments are `argv: [STRING, ...]`, vetted per element (10 read-only binaries; `find` side-effect flags, flag-embedded paths/assignments, `..`/`/.`, dotfiles, sensitive suffixes, out-of-prefix absolutes, and symlinks denied); the vetted array is forwarded verbatim for direct `execv(3)`-style execution -- no shell string parsing anywhere in the pipeline.

## Quick Start & Testing

```bash
make policy        # Compile policies/enterprise_example.json -> C++20 + Lean 4
make build         # Compile mcp-dfa-gate (-std=c++20 -O2 -Wall -Wextra -Wpedantic -pthread)
make test          # Run 25 hostile integration tests (tests/test_sidecar.py) -> 25/25
make test-seccomp  # Run 29 live-kernel red-team tests (tests/test_seccomp.py) -> 29/29
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

## Upgrade Notes (v0.5.0 -> v0.5.1)

* **Fence covers the whole descendant tree:** the sidecar is now a child subreaper (`PR_SET_CHILD_SUBREAPER`) and the fence discovers, stops, and sweeps every descendant at raise time — closing the v0.5.0 gap where a forked child holding an inherited socket, having never called a mediated syscall, escaped the sweep. Both new regressions (`test_silent_child_inherited_socket_severed`, `test_orphan_silent_child_socket_severed`) exfiltrate successfully against the v0.5.0 binary.
* **Fence failure fails closed (exit 43):** if any descendant cannot be verifiably stopped (e.g. stuck in uninterruptible `D` sleep, unreadable `/proc`, or the 1024-pid tracking cap is exceeded), the sidecar SIGKILLs the tree and exits 43 instead of resuming an unverified process. Mediated denies hold in every failure mode.
* **New static-deny coverage test:** `process_vm_readv` is pinned by a live test alongside `ptrace`.

## Upgrade Notes (v0.5.1 -> v0.6.0)

* **BREAKING -- `bash_workspace` now takes a typed argv array (H4 closed):** `arguments` changed from `{"command": "sha256sum /ws/file.txt"}` to `{"argv": ["sha256sum", "/ws/file.txt"]}`. The shell command-string parser is deleted; the downstream executor contract is direct `execv(3)` on the vetted array (never a shell), so the gate and the executor can no longer disagree about command grammar. Filenames containing spaces or metacharacters are now ordinary data and work end to end.
* **Error taxonomy split:** malformed `argv` (missing/non-array/empty, non-string/empty/oversized/non-printable elements, >256 elements, or the removed legacy `command` key) returns a clean JSON-RPC `-32602` with an actionable message -- nothing is forwarded and the session survives; well-formed but unvetted content keeps the v0.5 semantics (`-32001` plus permanent session absorption).
* **Downstream implementers:** exec the forwarded `argv` array directly (`shell=False` / `posix_spawn`-equivalent) and re-check `argv[0]` against the vetted allowlist as defense in depth; run with `cwd` pinned to the workspace (as `scripts/run_confined.sh` does).

## Upgrade Notes (v0.6.0 -> v0.6.1)

* **Strict fence by default (breaking for partial-sweep environments):** Any sweep failure (unreachable FDs, errors, non-convergence) now fails closed (taint stored, tree killed, exit **43**). Set `MCP_GATE_ALLOW_PARTIAL_FENCE=1` to explicitly accept the mediated-denies-only residual (loud startup + fence warnings).
* **Target-scoped discovery & exact socket identity:** Descendant discovery walks `/proc/<pid>/task/<tid>/children` recursively (falling back to `/proc` ppid-walk only if unavailable); socket deduplication uses exact `(st_dev, st_ino)` pairs; `pidfd_getfd` failures are classified into `vanished`/`eperm`/`other`.
* **`scripts/run_confined.sh`:** Added optional `MCP_GATE_UNSHARE_NET=1` (`--unshare-net`).

## Upgrade Notes (v0.6.1 -> v0.6.2)

* **Landlock `/proc/<pid>/mem` hardening (`MCP_GATE_LANDLOCK=1`, Linux 5.13+):** Opt-in Landlock ABI v1 ruleset allowlists `SAFE_PREFIX` and runtime directories while excluding `/proc`, blocking `/proc/self/mem` and `/proc/<pid>/mem` with `EACCES` (fails closed with exit **3** if Landlock is unavailable). Composes cleanly with `MCP_GATE_SECCOMP=1`.

## Known Residuals

See `SECURITY.md` for the full threat model and trust boundaries:

* All `v0.6` roadmap items (#3 H4 de-shell, #5 strict-by-default fence & `bwrap` coverage, #4 Landlock `/proc/<pid>/mem` hardening) are shipped; see `SECURITY.md` for remaining out-of-scope deployment boundaries.

## License

Copyright (c) 2026 Nicholas Clifford Maino III.

`mcp-dfa-gate` is dual-licensed under the **GNU Affero General Public License v3.0 (AGPLv3)** (see `LICENSE`) and a **Commercial License** (see `COMMERCIAL.md`) for proprietary production deployments.
