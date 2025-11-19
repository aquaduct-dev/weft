#!/usr/bin/env bash
# test/test-tunnel-graceful-shutdown.sh
# Purpose: end-to-end script that uses the compiled weft CLI to:
#  1) start a simple python http.server on a free port
#  2) start the weft server on a free port
#  3) start a weft tunnel that exposes the python server over the weft server
#  4) verify HTTP access works over the tunnel
#  5) kill the tunnel process
#  6) restart the tunnel process
#  7) verify HTTP access works over the new tunnel
#
# Exit codes:
#  0 = success
#  non-zero = failure

set -uo pipefail
IFS=$'\n\t'

# --- Configuration and Setup ---
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

# 2) Start Weft Server
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

echo "Starting weft server on port $SERVER_BIND_PORT..."
"$WEFT_BIN" server --verbose --port "$SERVER_BIND_PORT" --secret-file "$SECRET_FILE" >"$SERVER_LOG" 2>&1 &
pids+=($!)

# Wait for the secret file to be created
for i in $(seq 1 10); do
    if [ -f "$SECRET_FILE" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -f "$SECRET_FILE" ]; then
    echo "Failed to find secret file."
    cat "$SERVER_LOG"
    exit 2
fi

CONN_SECRET=$(cat "$SECRET_FILE" | tr -d '\n')
echo "Found connection secret: $CONN_SECRET"

# 3) Start Weft Tunnel
REMOTE_PORT1=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="tcp://127.0.0.1:${PY_PORT}"
REMOTE_URL1="tcp://127.0.0.1:${REMOTE_PORT1}"


wait_for_port "$SERVER_BIND_PORT"

echo "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_URL1..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL1" >"$TUNNEL_LOG" 2>&1 &
tunnel_pid=$!
pids+=($tunnel_pid)


# 4) Verify HTTP Access
wait_for_port "$REMOTE_PORT1"

echo "Attempting to connect to tunneled service at $REMOTE_URL1..."
set +e
CURL_OUTPUT=""
for i in $(seq 1 10); do
    CURL_OUTPUT=$(curl -s "http://127.0.0.1:$REMOTE_PORT1")
    CURL_EXIT=$?
    if echo "$CURL_OUTPUT" | grep -q "hello-from-http-server"; then
        break
    fi
    sleep 0.5
done
set -e

echo "curl exit: $CURL_EXIT"
echo "curl output: $CURL_OUTPUT"

if ! echo "$CURL_OUTPUT" | grep -q "hello-from-http-server"; then
    echo "FAIL: did not receive expected response over tunnel on first attempt."
    exit 3
fi

echo "Initial tunnel connection successful."

# 5) Kill the tunnel process
echo "Killing tunnel process..."
kill "$tunnel_pid"
# remove from pids array
pids=("${pids[@]/$tunnel_pid}")
sleep "$SHUTDOWN_WAIT"

# 6) Restart the tunnel process
echo "Restarting weft tunnel..."
TUNNEL_LOG2="$LOGDIR/tunnel2.log"
"$WEFT_BIN" tunnel --tunnel-name "$tunnelNameFlag" --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL1" >"$TUNNEL_LOG2" 2>&1 &
pids+=($!)

# 7) Verify HTTP Access on the new tunnel
wait_for_port "$REMOTE_PORT1"

echo "Attempting to connect to restarted tunneled service at $REMOTE_URL1..."
set +e
CURL_OUTPUT=""
for i in $(seq 1 10); do
    CURL_OUTPUT=$(timeout 1 curl -s "http://127.0.0.1:$REMOTE_PORT1")
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
    echo "SUCCESS: received expected response from python server over restarted tunnel."
        echo "server log -----"
    cat "$SERVER_LOG"
    echo "-----"
    echo "initial tunnel log -----"
    cat "$TUNNEL_LOG"
    echo "-----"
    echo "restarted tunnel log -----"
    cat "$TUNNEL_LOG2"
    echo "-----"
    echo "python log -----"
    cat "$PY_LOG"
    RESULT=0
else
    echo "FAIL: did not receive expected response over restarted tunnel."
    echo "-----"
    echo "server log -----"
    cat "$SERVER_LOG"
    echo "-----"
    echo "initial tunnel log -----"
    cat "$TUNNEL_LOG"
    echo "-----"
    echo "restarted tunnel log -----"
    cat "$TUNNEL_LOG2"
    echo "-----"
    echo "python log -----"
    cat "$PY_LOG"
    RESULT=4
fi

exit "$RESULT"
