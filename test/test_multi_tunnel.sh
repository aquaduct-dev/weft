#!/usr/bin/env bash
# test/test_multi_tunnel.sh
# Purpose: Verify that a single 'weft tunnel' command can create multiple tunnels.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# 1) Start two Python HTTP Servers
PY_PORT1=$(find_free_port)
PY_LOG1="$LOGDIR/python1.log"
DIR1="$LOGDIR/dir1"
mkdir -p "$DIR1"
echo "hello-from-server-1" > "$DIR1/index.html"

log "Starting python server 1 on port $PY_PORT1..."
python3 -m http.server "$PY_PORT1" --directory "$DIR1" >"$PY_LOG1" 2>&1 &
pids+=($!)

PY_PORT2=$(find_free_port)
PY_LOG2="$LOGDIR/python2.log"
DIR2="$LOGDIR/dir2"
mkdir -p "$DIR2"
echo "hello-from-server-2" > "$DIR2/index.html"

log "Starting python server 2 on port $PY_PORT2..."
python3 -m http.server "$PY_PORT2" --directory "$DIR2" >"$PY_LOG2" 2>&1 &
pids+=($!)

wait_for_port "$PY_PORT1"
wait_for_port "$PY_PORT2"

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
    exit 2
fi

CONN_SECRET=$(cat "$SECRET_FILE" | tr -d '\n')
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
wait_for_port "$SERVER_BIND_PORT"

# 3) Start Weft Tunnel with TWO tunnels
REMOTE_PORT1=$(find_free_port)
REMOTE_PORT2=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"

LOCAL_URL1="http://127.0.0.1:${PY_PORT1}"
REMOTE_URL1="http://127.0.0.1:${REMOTE_PORT1}"

LOCAL_URL2="http://127.0.0.1:${PY_PORT2}"
REMOTE_URL2="http://127.0.0.1:${REMOTE_PORT2}"

log "Starting multiple weft tunnels..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL1" "$REMOTE_URL1" "$LOCAL_URL2" "$REMOTE_URL2" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# 4) Verify both tunnels
wait_for_port "$REMOTE_PORT1"
wait_for_port "$REMOTE_PORT2"

log "Verifying tunnel 1..."
set +e
CURL_OUTPUT1=$(curl -s "http://127.0.0.1:$REMOTE_PORT1")
log "Tunnel 1 output: $CURL_OUTPUT1"

log "Verifying tunnel 2..."
CURL_OUTPUT2=$(curl -s "http://127.0.0.1:$REMOTE_PORT2")
log "Tunnel 2 output: $CURL_OUTPUT2"
set -e

if echo "$CURL_OUTPUT1" | grep -q "hello-from-server-1" && echo "$CURL_OUTPUT2" | grep -q "hello-from-server-2"; then
    log "SUCCESS: both tunnels working correctly."
    RESULT=0
else
    log "FAIL: one or both tunnels failed."
    RESULT=3
fi

exit "$RESULT"
