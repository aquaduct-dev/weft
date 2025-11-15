#!/usr/bin/env bash
# test/test_tcp_proxy.sh
# Purpose: end-to-end script that uses the compiled weft CLI to:
#  1) start a simple python http.server on a free port
#  2) start the weft proxy that proxies to the python server
#  3) verify HTTP access works over the proxy
#
PROTO=${PROTO:-tcp}

set -uo pipefail
IFS=$'\n\t'


WEFT_BIN=$(find . | grep -e "/weft$")
LOGDIR=$(mktemp -d /tmp/weft-test-XXXX)
SHUTDOWN_WAIT=1
RESULT=1 # Default to failure

# Keep track of PIDs to kill them individually.
pids=()

# Cleanup function to be called on exit.
cleanup() {
    echo "Cleaning up..."
    # Kill all tracked processes in reverse order
    for pid in "${pids[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    
    # Decide whether to keep logs.
    if [[ "$RESULT" -ne 0 ]]; then
        echo "Test failed. Logs retained at $LOGDIR"
    else
        rm -rf "$LOGDIR"
        echo "Test passed."
    fi
}

trap cleanup EXIT

echo "Logs will be written to $LOGDIR"

# --- Port and Process Management ---

# Find a free TCP port.
find_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'
}

# Wait for a port to be open.
wait_for_port() {
    local port=$1
    local host=${2:-127.0.0.1}
    local timeout=${3:-10}
    echo "Waiting for $host:$port to be open..."
    for i in $(seq 1 "$timeout"); do
        if nc -z "$host" "$port" >/dev/null 2>&1;
        then
            echo "$host:$port is open."
            return 0
        fi
        sleep 0.5
    done
    echo "Timed out waiting for $host:$port."
    return 1
}

# --- Test Steps ---

# 1) Start Python HTTP Server
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python.log"
# Create a dummy index.html for the http.server to serve
echo "hello-from-http-server" > "$LOGDIR/index.html"

echo "Starting python http.server on port $PY_PORT..."
python3 -m http.server "$PY_PORT" --directory "$LOGDIR" >"$PY_LOG" 2>&1 &
pids+=($!)
wait_for_port "$PY_PORT"
echo "Python http.server is ready."

# 2) Start Weft Proxy
PROXY_LISTEN_PORT=$(find_free_port)
PROXY_LOG="$LOGDIR/proxy.log"
TARGET_URL="http://127.0.0.1:$PY_PORT"

echo "Starting weft proxy on port $PROXY_LISTEN_PORT, targeting $TARGET_URL..."
"$WEFT_BIN" proxy --verbose "${PROTO}://127.0.0.1:$PY_PORT" "${PROTO}://127.0.0.1:$PROXY_LISTEN_PORT" >"$PROXY_LOG" 2>&1 &
pids+=($!)

wait_for_port "$PROXY_LISTEN_PORT"

# 3) Verify HTTP Access through Proxy
echo "Attempting to connect to proxied service at http://127.0.0.1:$PROXY_LISTEN_PORT..."
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
    echo "SUCCESS: received expected response from python server over proxy."
    RESULT=0
else
    echo "FAIL: did not receive expected response over proxy."
    echo "-----"
    echo "proxy log -----"
    cat "$PROXY_LOG"
    echo "-----"
    echo "python log -----"
    cat "$PY_LOG"
    RESULT=3
fi

exit "$RESULT"
