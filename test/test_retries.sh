#!/usr/bin/env bash
# test/test_retries.sh
# Purpose: Verify the --retries flag controls healthcheck failure threshold.
# The tunnel should shut down after N consecutive healthcheck failures.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# --- 1) Start weft server ---
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

log "Starting weft server on port $SERVER_BIND_PORT..."
"$WEFT_BIN" server --verbose --port "$SERVER_BIND_PORT" --secret-file "$SECRET_FILE" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
pids+=($SERVER_PID)

# Wait for the secret file to be created
for i in $(seq 1 10); do
    if [ -f "$SECRET_FILE" ]; then break; fi
    sleep 0.5
done

if [ ! -f "$SECRET_FILE" ]; then
    log "Failed to find secret file."
    cat "$SERVER_LOG"
    exit 2
fi

CONN_SECRET=$(cat "$SECRET_FILE" | tr -d '\n')
log "Found connection secret: $CONN_SECRET"

# --- 2) Start weft tunnel with --retries 2 ---
LOCAL_PORT=$(find_free_port)
REMOTE_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="tcp://127.0.0.1:${LOCAL_PORT}"
REMOTE_URL="tcp://127.0.0.1:${REMOTE_PORT}"

wait_for_port "$SERVER_BIND_PORT"

log "Starting weft tunnel with --retries 2..."
"$WEFT_BIN" tunnel --verbose --retries 2 "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!
pids+=($TUNNEL_PID)

# Give the tunnel time to establish
sleep 2

# Verify tunnel is running
if ! ps -p $TUNNEL_PID > /dev/null; then
    log "Tunnel failed to start"
    cat "$TUNNEL_LOG"
    exit 3
fi
log "Tunnel is running."

# --- 3) Stop server to trigger healthcheck failures ---
log "Stopping server to trigger healthcheck failures..."
kill $SERVER_PID
# Remove from pids array so cleanup doesn't try to kill it again
pids=("${pids[@]/$SERVER_PID}")

# --- 4) Wait for tunnel to detect failures and shut down ---
# Healthcheck interval is 5s. With retries=2, we expect:
# - Fail 1 at ~5s
# - Fail 2 at ~10s -> shutdown
# Give it 20 seconds to be safe.
log "Waiting for tunnel to shut down after 2 failed healthchecks..."
TIMEOUT=20
INTERVAL=1
ELAPSED=0
while ps -p $TUNNEL_PID > /dev/null 2>&1; do
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
    if [ $ELAPSED -ge $TIMEOUT ]; then
        log "FAIL: Tunnel did not shut down within ${TIMEOUT}s."
        kill $TUNNEL_PID 2>/dev/null || true
        cat "$TUNNEL_LOG"
        exit 4
    fi
done

log "Tunnel shut down as expected."

# --- 5) Verify log messages ---
if grep -q "Healthcheck failed, incrementing failure count" "$TUNNEL_LOG"; then
    log "Found failure increment log [OK]"
else
    log "FAIL: Missing 'Healthcheck failed, incrementing failure count' in tunnel log."
    cat "$TUNNEL_LOG"
    exit 5
fi

if grep -q "Healthcheck failed too many times" "$TUNNEL_LOG"; then
    log "Found shutdown log [OK]"
else
    log "FAIL: Missing 'Healthcheck failed too many times' in tunnel log."
    cat "$TUNNEL_LOG"
    exit 6
fi

log "SUCCESS: --retries flag works correctly."
RESULT=0
exit $RESULT
