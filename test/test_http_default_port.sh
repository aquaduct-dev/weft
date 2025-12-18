#!/usr/bin/env bash
# test/test_http_default_port.sh
# Purpose: end-to-end HTTP tunnel test to verify that if the remote target URL has no
# port specified, it defaults to 80 for HTTP.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

# --- Setup ---
TMPDIR="$(mktemp -d)"

log "Logs will be written to $LOGDIR"

# --- Start weft server ---
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

log "Starting weft server on port $SERVER_BIND_PORT..."
"$WEFT_BIN" server --verbose --port "$SERVER_BIND_PORT" --secret-file "$SECRET_FILE"  >"$SERVER_LOG" 2>&1 &
pids+=($!)

# Wait for the secret file to be created
for i in $(seq 1 10); do
  if [ -f "$SECRET_FILE" ]; then break; fi
  sleep 0.5
done

if [ ! -f "$SECRET_FILE" ]; then
  log "Failed to find secret file."
  cat "$SERVER_LOG"
  exit 6
fi

CONN_SECRET=$(cat "$SECRET_FILE" | tr -d '\n')
log "Found connection secret: $CONN_SECRET"

# --- Start weft tunnel ---
REMOTE_PORT=$(find_free_port) # This is the client's local listening port
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="http://127.0.0.1" # The actual backend
REMOTE_TARGET="http://localhost:23422" # The remote target, port omitted for testing default

wait_for_port "$SERVER_BIND_PORT"

log "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_TARGET (default 80 expected)"
# The weft tunnel command takes the client's local listening port as a separate argument to the REMOTE_TARGET
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_TARGET"  >"$TUNNEL_LOG" 2>&1 &
pids+=($!)
sleep 0.5
if cat "$TUNNEL_LOG" | grep "Failed to start proxy"; then
  log "FAIL: proxy did not start"
  log "-----"
  echo "server log -----"
  cat "$SERVER_LOG"
  log "-----"
  echo "tunnel log -----"
  cat "$TUNNEL_LOG"
  log "-----"
  echo "python log -----"
  cat "$PY_LOG"
  RESULT=3
else
  log "SUCCESS: proxy started OK"
  RESULT=0
fi

exit "$RESULT"
