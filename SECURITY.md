# Security Model and Trust Boundaries (mcp-dfa-gate v0.2)

## 1. Formally Verified Properties (Lean 4)
`lean/lattice_proof.lean` proves two universal theorems over all 64-bit taint-lattice policies and arbitrary-length traces (no Mathlib, no `sorry`, no `native_decide`):
1. `halted_rejects_nonempty`: Once `halted = true`, every non-empty trace is rejected.
2. `universal_non_interference`: For any `LatticeState` with taint bit `i` set and any arbitrary-length trace containing a rule with `clearance[i] = false`, `run_trace` evaluates to `false`.

## 2. Runtime Adapter Guarantees (src/mcp_sidecar.cpp)
Enforced in C++20 outside the Lean model and verified by 24 black-box tests in `tests/test_sidecar.py`:
* Strict 7-bit ASCII transport, 1 MiB line cap, duplicate JSON key rejection, and JSON-RPC `id` type validation.
* Fail-closed method allowlist (`resources/*`, `prompts/*`, `sampling/*` are blocked).
* `tools/call` frames are reconstructed from whitelisted fields only (`path`, `command`, or `url`).
* `read_file` paths are canonicalized beneath an `O_DIRECTORY` workspace descriptor via `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` + `fstat(S_ISREG)`. Failures taint the session (`LABEL_SECRETS`) and refuse forwarding (`-32002`).
* `bash_workspace` allows only 10 read-only binaries and rejects shell metacharacters, `..`, `/.`, dotfiles, sensitive suffixes (`.pem`, `.key`, `.p12`, `.sql`, `.env`, `.kdbx`), flag-embedded paths, and symlinks.

## 3. Out-of-Scope / Caller Responsibilities
* **Downstream `cwd` and filesystem confinement:** Deployers must confine the downstream server inside `SAFE_PREFIX` (see `scripts/run_confined.sh` using `bwrap`).
* **Path TOCTOU between gate and downstream:** Because MCP passes file paths as strings over JSON-RPC, a concurrent writer in `SAFE_PREFIX` could swap a file after the gate's `openat2` check. Mounting `SAFE_PREFIX` read-only in the downstream sandbox eliminates this window.
* **SSRF filtering:** `http_fetch` / `fetch_url` are blocked once tainted, but internal/metadata IP filtering while untainted is a downstream responsibility.
* **C++ to Lean equivalence:** `mcp_lattice::transition` and Lean `step` are matched by inspection and shared policy generation (`tools/policy_compiler.py`), not verified compiler extraction.
