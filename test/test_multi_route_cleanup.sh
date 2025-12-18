#!/usr/bin/env bash
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# 1) Start two Python HTTP Servers for different paths
PY_PORT1=$(find_free_port)
PY_LOG1="$LOGDIR/python1.log"
echo "hello-from-upstream-1" > "$LOGDIR/index1.html"
python3 -m http.server "$PY_PORT1" --directory "$LOGDIR" >"$PY_LOG1" 2>&1 &
pids+=($!)
wait_for_port "$PY_PORT1"

PY_PORT2=$(find_free_port)
PY_LOG2="$LOGDIR/python2.log"
echo "hello-from-upstream-2" > "$LOGDIR/index2.html"
python3 -m http.server "$PY_PORT2" --directory "$LOGDIR" >"$PY_LOG2" 2>&1 &
pids+=($!)
wait_for_port "$PY_PORT2"

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

# 3) Start two Weft Tunnels for the same host but different paths
# Tunnel 1: /v1 -> Upstream 1
# Tunnel 2: /v2 -> Upstream 2
TUNNEL_BIND_PORT=$(find_free_port)
REMOTE_HOST="multi.example.com"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"

log "Starting weft tunnel 1 (/v1)..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "http://127.0.0.1:${PY_PORT1}" "http://${REMOTE_HOST}:${TUNNEL_BIND_PORT}/v1?v=1" >"$LOGDIR/tunnel1.log" 2>&1 &
TUNNEL1_PID=$!
pids+=($TUNNEL1_PID)

log "Starting weft tunnel 2 (/v2)..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "http://127.0.0.1:${PY_PORT2}" "http://${REMOTE_HOST}:${TUNNEL_BIND_PORT}/v2?v=2" >"$LOGDIR/tunnel2.log" 2>&1 &
TUNNEL2_PID=$!
pids+=($TUNNEL2_PID)

wait_for_port "$TUNNEL_BIND_PORT"

# 4) Verify both work
log "Verifying both tunnels work..."
OUT1=$(curl -s -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/v1/index1.html?v=1")
OUT2=$(curl -s -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/v2/index2.html?v=2")

if [[ "$OUT1" == "hello-from-upstream-1" ]] && [[ "$OUT2" == "hello-from-upstream-2" ]]; then
    log "SUCCESS: Both tunnels are working."
else
    log "FAILURE: Initial verification failed. OUT1=$OUT1, OUT2=$OUT2"
    exit 1
fi

# 5) Close tunnel 1
log "Closing tunnel 1..."
kill -TERM "$TUNNEL1_PID"
sleep 2 # Wait for cleanup on server

# 6) Verify tunnel 1 is gone and tunnel 2 still works
log "Verifying cleanup..."
CODE1=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/v1/index1.html?v=1")
OUT2_AGAIN=$(curl -s -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/v2/index2.html?v=2")

log "Tunnel 1 status code: $CODE1"
log "Tunnel 2 output: $OUT2_AGAIN"

if [[ "$CODE1" == "404" ]] && [[ "$OUT2_AGAIN" == "hello-from-upstream-2" ]]; then
    log "SUCCESS: Multi-route cleanup worked!"
    RESULT=0
else
    log "FAILURE: Cleanup verification failed. CODE1=$CODE1, OUT2=$OUT2_AGAIN"
    RESULT=1
fi

exit "$RESULT"
