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

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

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

# 2) Start Weft Server
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

log "Starting weft server on port $SERVER_BIND_PORT..."
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
    log "Failed to find secret file."
    cat "$SERVER_LOG"
    exit 2
fi

CONN_SECRET=$(cat "$SECRET_FILE" | tr -d '\n')
log "Found connection secret: $CONN_SECRET"

# 3) Start Weft Tunnel
REMOTE_PORT1=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="tcp://127.0.0.1:${PY_PORT}"
REMOTE_URL1="tcp://127.0.0.1:${REMOTE_PORT1}"
tunnelNameFlag="graceful-shutdown-test"


wait_for_port "$SERVER_BIND_PORT"

log "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_URL1..."
"$WEFT_BIN" tunnel --tunnel-name "$tunnelNameFlag" --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL1" >"$TUNNEL_LOG" 2>&1 &
tunnel_pid=$!
pids+=($tunnel_pid)


# 4) Verify HTTP Access
wait_for_port "$REMOTE_PORT1"

log "Attempting to connect to tunneled service at $REMOTE_URL1..."
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
    log "FAIL: did not receive expected response over tunnel on first attempt."
    exit 3
fi

log "Initial tunnel connection successful."

# 5) Kill the tunnel process
log "Killing tunnel process..."
kill "$tunnel_pid"
# remove from pids array
pids=("${pids[@]/$tunnel_pid}")
sleep "$SHUTDOWN_WAIT"

# 6) Restart the tunnel process
log "Restarting weft tunnel..."
TUNNEL_LOG2="$LOGDIR/tunnel2.log"
"$WEFT_BIN" tunnel --tunnel-name "$tunnelNameFlag" --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL1" >"$TUNNEL_LOG2" 2>&1 &
pids+=($!)

# 7) Verify HTTP Access on the new tunnel
wait_for_port "$REMOTE_PORT1"

log "Attempting to connect to restarted tunneled service at $REMOTE_URL1..."
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
    log "SUCCESS: received expected response from python server over restarted tunnel."
        echo "server log -----"
    cat "$SERVER_LOG"
    log "-----"
    echo "initial tunnel log -----"
    cat "$TUNNEL_LOG"
    log "-----"
    echo "restarted tunnel log -----"
    cat "$TUNNEL_LOG2"
    log "-----"
    echo "python log -----"
    cat "$PY_LOG"
    RESULT=0
else
    log "FAIL: did not receive expected response over restarted tunnel."
    log "-----"
    echo "server log -----"
    cat "$SERVER_LOG"
    log "-----"
    echo "initial tunnel log -----"
    cat "$TUNNEL_LOG"
    log "-----"
    echo "restarted tunnel log -----"
    cat "$TUNNEL_LOG2"
    log "-----"
    echo "python log -----"
    cat "$PY_LOG"
    RESULT=4
fi

exit "$RESULT"
