#!/usr/bin/env bash
# test/test-udp.sh
# Purpose: end-to-end script that uses the compiled weft CLI to:
#  1) start a simple UDP echo server on a free port
#  2) start the weft server on a free port
#  3) start a weft tunnel that exposes the UDP echo server over the weft server
#  4) verify UDP access works over the tunnel

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

SHUTDOWN_WAIT=1

log "Logs will be written to $LOGDIR"

# 1) Start UDP echo server (python)
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python_udp.log"
cat > "$LOGDIR/udp_echo.py" <<'PY'
#!/usr/bin/env python3
import socket
import sys
port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", port))
# Simple echo loop
while True:
    data, addr = sock.recvfrom(65535)
    if not data:
        continue
    sock.sendto(data, addr)
PY
chmod +x "$LOGDIR/udp_echo.py"
python3 "$LOGDIR/udp_echo.py" "$PY_PORT" >"$PY_LOG" 2>&1 &
pids+=($!)
wait_for_udp_port
log "Python UDP echo server is ready on port $PY_PORT."

# 2) Start Weft Server
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

log "Starting weft server on port $SERVER_BIND_PORT..."
"$WEFT_BIN" server --verbose --port "$SERVER_BIND_PORT" --secret-file "$SECRET_FILE" >"$SERVER_LOG" 2>&1 &
pids+=($!)

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

# 3) Start Weft Tunnel (UDP)
REMOTE_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="udp://127.0.0.1:${PY_PORT}"
REMOTE_URL="udp://127.0.0.1:${REMOTE_PORT}"


log "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_URL..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# Give processes time to settle
sleep 1

# 4) Verify UDP access by sending a packet and expecting an echo
log "Attempting to send UDP packet to tunneled service at 127.0.0.1:$REMOTE_PORT..."
set +e
PY_SEND_RECV="$LOGDIR/udp_test.py"
cat > "$PY_SEND_RECV" <<'PY'
#!/usr/bin/env python3
import socket, sys, time
host = "127.0.0.1"
port = int(sys.argv[1])
msg = b"hello-from-udp-server"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.sendto(msg, (host, port))
try:
    data, n = sock.recvfrom(65535)
    print(data.decode())
except Exception as e:
    print("ERR:"+str(e))
    sys.exit(2)
PY
chmod +x "$PY_SEND_RECV"

OUT=$("$PY_SEND_RECV" "$REMOTE_PORT")
EXIT=$?
set -e

echo "udp test exit: $EXIT"
echo "udp test output: $OUT"

if echo "$OUT" | grep -q "hello-from-udp-server"; then
    log "SUCCESS: received expected UDP echo from server over tunnel."
    RESULT=0
else
    log "FAIL: did not receive expected UDP response over tunnel."
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
fi

exit "$RESULT"