#!/usr/bin/env bash
set -uo pipefail

# Find weft binary
if [[ -n "${RUNFILES_DIR:-}" && -f "${RUNFILES_DIR}/_main/weft" ]]; then
    WEFT_BIN="${RUNFILES_DIR}/_main/weft"
elif [[ -f "./weft" ]]; then
    WEFT_BIN="./weft"
else
    WEFT_BIN=$(find . -name weft -type f | head -n 1)
fi

if [[ -z "$WEFT_BIN" || ! -f "$WEFT_BIN" ]]; then
    # Fallback for bazel raw binary
    WEFT_BIN=$(find . -name weft_raw -type f | head -n 1)
fi

LOGDIR=$(mktemp -d /tmp/weft-test-XXXX)
RESULT=1
pids=()

log() {
    echo "[$(basename "$0")] $*" >&2
}

cleanup() {
    log "Cleaning up..."
    for pid in "${pids[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    
    if [[ "$RESULT" -ne 0 ]]; then
        log "Test failed. Logs retained at $LOGDIR"
        # Optional: print logs if in CI or if requested
        if [[ "${VERBOSE:-0}" -ne 0 ]]; then
            grep "" "$LOGDIR"/*.log || true
        fi
    else
        rm -rf "$LOGDIR"
        log "Test passed."
    fi
}

find_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'
}

wait_for_port() {
    local port=$1
    local host=${2:-127.0.0.1}
    local timeout=${3:-10}
    log "Waiting for $host:$port to be open..."
    for i in $(seq 1 "$timeout"); do
        if nc -z "$host" "$port" >/dev/null 2>&1; then
            log "$host:$port is open."
            return 0
        fi
        sleep 0.5
    done
    log "Timed out waiting for $host:$port."
    return 1
}

wait_for_udp_port() {
    # For UDP there's no connect check; we just sleep briefly to allow bind.
    sleep 0.5
}
