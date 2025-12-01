#!/usr/bin/env bash
# test/test_http_default_port.sh
# Purpose: end-to-end HTTP tunnel test to verify that if the remote target URL has no
# port specified, it defaults to 80 for HTTP.
#
# Exit codes:
#  0 = success
#  non-zero = failure

set -uo pipefail
IFS=$'\n\t'

# --- Helpers ---
log() {
  echo "test_http_default_port: $*" >&2
}

cleanup() {
  if [[ "${RESULT:-1}" -ne 0 ]]; then
    echo "Test failed. Logs retained at $LOGDIR"
  else
    rm -rf "$LOGDIR"
    echo "Test passed."
  fi

  # Kill all tracked processes
  for pid in "${pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done

  if [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# --- Setup ---
LOGDIR="$(mktemp -d /tmp/weft-test-XXXX)"
TMPDIR="$(mktemp -d)"
RESULT=1
pids=()
WEFT_BIN=$(find . | grep -e "/weft$")


echo "Logs will be written to $LOGDIR"
# --- Port helpers ---
find_free_port() {
  python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("",0))
print(s.getsockname()[1])
s.close()
PY
}

wait_for_port() {
  local port=$1
  local host=${2:-127.0.0.1}
  local timeout=${3:-10}
  echo "Waiting for $host:$port to be open..."
  for i in $(seq 1 "$timeout"); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      echo "$host:$port is open."
      return 0
    fi
    sleep 0.5
  done
  echo "Timed out waiting for $host:$port."
  return 1
}

# --- Start weft server ---
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

echo "Starting weft server on port $SERVER_BIND_PORT..."
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
echo "Found connection secret: $CONN_SECRET"

# --- Start weft tunnel ---
REMOTE_PORT=$(find_free_port) # This is the client's local listening port
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="http://127.0.0.1" # The actual backend
REMOTE_TARGET="http://localhost:23422" # The remote target, port omitted for testing default

wait_for_port "$SERVER_BIND_PORT"

echo "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_TARGET (default 80 expected)"
# The weft tunnel command takes the client's local listening port as a separate argument to the REMOTE_TARGET
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_TARGET"  >"$TUNNEL_LOG" 2>&1 &
pids+=($!)
sleep 0.5
if cat "$TUNNEL_LOG" | grep "Failed to start proxy"; then
  echo "FAIL: proxy did not start"
  echo "-----"
  echo "server log -----"
  cat "$SERVER_LOG"
  echo "-----"
  echo "tunnel log -----"
  cat "$TUNNEL_LOG"
  echo "-----"
  echo "python log -----"
  cat "$PY_LOG"
  RESULT=3
else
  echo "SUCCESS: proxy started OK"
  RESULT=0
fi

exit "$RESULT"
