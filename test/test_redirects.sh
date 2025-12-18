#!/usr/bin/env bash
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# No upstream needed for redirect test, but let's have one just in case we hit it.
PY_PORT=$(find_free_port)
python3 -m http.server "$PY_PORT" >/dev/null 2>&1 &
pids+=($!)

# 2) Start Weft Server
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

log "Starting weft server on port $SERVER_BIND_PORT..."
"$WEFT_BIN" server --verbose --port "$SERVER_BIND_PORT" --secret-file "$SECRET_FILE" >"$SERVER_LOG" 2>&1 &
pids+=($!)

for i in $(seq 1 10); do
    if [ -f "$SECRET_FILE" ]; then break; fi
    sleep 0.5
done

if [ ! -f "$SECRET_FILE" ]; then
    log "Failed to find secret file."
    exit 2
fi
CONN_SECRET=$(cat "$SECRET_FILE" | tr -d '\n')

# 3) Start Weft Tunnel with Redirect
# Mapping: http://my-app.example.com/#redirect -> http://google.com (or any other target)
# Request to /test should get 302 to http://google.com
TUNNEL_BIND_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
REMOTE_HOST="redirect.example.com"
TARGET_REDIRECT="http://google.test"

WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="${TARGET_REDIRECT}/#redirect"
REMOTE_URL="http://${REMOTE_HOST}:${TUNNEL_BIND_PORT}"

wait_for_port "$SERVER_BIND_PORT"

log "Starting weft tunnel..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# 4) Verify Redirect
wait_for_port "$TUNNEL_BIND_PORT"

log "Testing Redirect..."

# -L to follow redirects, but we want to check the Location header
RESPONSE_HEADERS=$(curl -s -I -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/test")
log "Got response headers:"
log "$RESPONSE_HEADERS"

if echo "$RESPONSE_HEADERS" | grep -q "HTTP/1.1 302 Found" && echo "$RESPONSE_HEADERS" | grep -q "Location: ${TARGET_REDIRECT}"; then
    log "SUCCESS: Redirect worked!"
    RESULT=0
else
    log "FAILURE: Redirect did not work as expected."
    RESULT=1
fi

exit "$RESULT"
