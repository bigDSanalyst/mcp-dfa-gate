# mcp-dfa-gate (v0.2)

Zero-dependency C++20 `stdio` JSON-RPC security sidecar for Model Context Protocol (MCP) agents, backed by a 64-bit bitwise taint-lattice engine, a JSON policy-to-proof compiler, and a Lean 4 universal Non-Interference proof.

## Key Properties

* **64-bit Taint-Lattice Engine (`include/lattice_engine.hpp`):** Models up to 64 independent taint domains (2^64 effective DFA states) via branchless bitwise transitions (`1.99 ns` avg over 10,000,000 calls). Non-copyable, non-movable, non-resettable, lvalue-ref-qualified (`&`).
* **Policy-to-Proof Compiler (`tools/policy_compiler.py`):** Compiles a canonical JSON policy (`policies/enterprise_example.json`) into both `include/generated_policy.hpp` (with a SHA-256 commitment) and `lean/generated_policy_cert.lean`.
* **Lean 4 Universal Non-Interference (`lean/lattice_proof.lean`):** Kernel-checked on Lean 4 (no Mathlib, no `sorry`, no `native_decide`; standard `BitVec` axioms `[propext, Classical.choice, Quot.sound]`). Proves by induction that once any taint bit `i` is set, no arbitrary-length trace containing a tool lacking clearance for `i` can succeed.
* **Hardened C++20 Sidecar (`src/mcp_sidecar.cpp`):**
  * Strict 7-bit ASCII transport, 1 MiB line cap, duplicate JSON key rejection, and JSON-RPC `id` type validation.
  * Fail-closed method allowlist (`initialize`, `initialized`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`).
  * Rebuilds `tools/call` frames from whitelisted fields; raw client JSON is never forwarded.
  * Linux `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` + `fstat(S_ISREG)` canonicalization (with `O_NOFOLLOW` fallback).
  * Vetted read-only command allowlist for `bash_workspace` (blocks metacharacters, flag-embedded paths, dotfiles, sensitive suffixes, and symlinks).

## Quick Start

```bash
make policy   # Compile policies/enterprise_example.json -> C++20 + Lean 4
make build    # Compile mcp-dfa-gate (-std=c++20 -O2 -Wall -Wextra -Wpedantic)
make test     # Run 24 hostile integration tests (tests/test_sidecar.py)
make verify   # Check Lean 4 universal Non-Interference proof
```

## Usage

```bash
./mcp-dfa-gate /workspace/public/ -- python3 -m your_mcp_server
```

For production OS confinement (read-only workspace bind mount + `cwd` lock):

```bash
./scripts/run_confined.sh /workspace/public -- python3 -m your_mcp_server
```

See `SECURITY.md` for the exact threat model and out-of-scope boundaries.
