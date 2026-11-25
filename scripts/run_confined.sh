#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 SAFE_PREFIX -- DOWNSTREAM argv..." >&2
  exit 2
fi

SAFE_PREFIX="${1%/}/"
shift
if [[ "$1" != "--" ]]; then
  echo "expected '--' after SAFE_PREFIX" >&2
  exit 2
fi
shift

GATE_BIN="${MCP_GATE_BIN:-$(dirname "$0")/../mcp-dfa-gate}"

# Optional network-namespace isolation (not equivalent to FD-sweep
# verification; does not cover AF_UNIX/socketpair channels).
NET_ARGS=()
if [[ "${MCP_GATE_UNSHARE_NET:-0}" == "1" ]]; then
  NET_ARGS+=(--unshare-net)
fi

exec "$GATE_BIN" "$SAFE_PREFIX" -- \
  bwrap \
    --ro-bind /usr /usr \
    --ro-bind /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind /bin /bin \
    --ro-bind-try /etc/resolv.conf /etc/resolv.conf \
    --ro-bind-try /etc/ssl/certs /etc/ssl/certs \
    --ro-bind "$SAFE_PREFIX" "$SAFE_PREFIX" \
    --proc /proc \
    --dev /dev \
    --chdir "$SAFE_PREFIX" \
    --unshare-pid \
    "${NET_ARGS[@]}" \
    --die-with-parent \
    --new-session \
    "$@"
