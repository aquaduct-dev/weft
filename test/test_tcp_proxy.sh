#!/usr/bin/env bash
# test/test_tcp_proxy.sh
# Purpose: end-to-end script that uses the compiled weft CLI to:
#  1) start a simple python http.server on a free port
#  2) start the weft proxy that proxies to the python server
#  3) verify HTTP access works over the proxy
#
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

PROTO=${PROTO:-tcp}
SHUTDOWN_WAIT=1

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Python HTTP Server
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python.log"
# Create a dummy index.html for the http.server to serve
echo "hello-from-http-server" > "$LOGDIR/index.html"

log "Starting python http.server on port $PY_PORT..."
python3 -m http.server "$PY_PORT" --directory "$LOGDIR" >"$PY_LOG" 2>&1 &
pids+=($!)
wait_for_port "$PY_PORT"
log "Python http.server is ready."

# 2) Start Weft Proxy
PROXY_LISTEN_PORT=$(find_free_port)
PROXY_LOG="$LOGDIR/proxy.log"
TARGET_URL="http://127.0.0.1:$PY_PORT"

log "Starting weft proxy on port $PROXY_LISTEN_PORT, targeting $TARGET_URL..."
"$WEFT_BIN" proxy --verbose "${PROTO}://127.0.0.1:$PY_PORT" "${PROTO}://127.0.0.1:$PROXY_LISTEN_PORT" >"$PROXY_LOG" 2>&1 &
pids+=($!)

wait_for_port "$PROXY_LISTEN_PORT"

# 3) Verify HTTP Access through Proxy
log "Attempting to connect to proxied service at http://127.0.0.1:$PROXY_LISTEN_PORT..."
set +e
CURL_OUTPUT=""
for i in $(seq 1 10); do
    CURL_OUTPUT=$(curl -s "http://127.0.0.1:$PROXY_LISTEN_PORT")
    CURL_EXIT=$?
    if echo "$CURL_OUTPUT" | grep -q "hello-from-http-server"; then
        break
    fi
    sleep 0.5
done
set -e

echo "curl exit: $CURL_EXIT"
echo "curl output: $CURL_OUTPUT"

if echo "$CURL_OUTPUT" | grep -q "hello-from-http-server"; then
    log "SUCCESS: received expected response from python server over proxy."
    RESULT=0
else
    log "FAIL: did not receive expected response over proxy."
    log "-----"
    echo "proxy log -----"
    cat "$PROXY_LOG"
    log "-----"
    echo "python log -----"
    cat "$PY_LOG"
    RESULT=3
fi

exit "$RESULT"
