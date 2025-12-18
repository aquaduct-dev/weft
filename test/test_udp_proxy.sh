#!/usr/bin/env bash
# test/test_udp_proxy.sh
# Purpose: end-to-end script that uses the compiled weft CLI to:
#  1) start a simple nc udp server on a free port
#  2) start the weft proxy that proxies to the nc server
#  3) verify UDP access works over the proxy
#
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

PROTO=${PROTO:-udp}
SHUTDOWN_WAIT=1

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Python UDP Server
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python_udp.log"
RESPONSE="hello-from-python-udp-server"

# Embed Python UDP server script
cat <<EOF > "$LOGDIR/udp_server.py"
import socket
import sys
import time

UDP_IP = "127.0.0.1"
UDP_PORT = int(sys.argv[1])
RESPONSE = sys.argv[2]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Python UDP server listening on {UDP_IP}:{UDP_PORT}")

while True:
    try:
        data, addr = sock.recvfrom(1024)
        print(f"Received message: {data.decode()} from {addr}")
        sock.sendto(RESPONSE.encode(), addr)
        print(f"Sent response: {RESPONSE} to {addr}")
    except socket.timeout:
        # This can happen if no data is received for a while, just continue
        pass
    except Exception as e:
        print(f"Error in UDP server: {e}")
        break
EOF

log "Starting python UDP server on port $PY_PORT..."
python3 "$LOGDIR/udp_server.py" "$PY_PORT" "$RESPONSE" >"$PY_LOG" 2>&1 &
pids+=($!)
wait_for_port "$PY_PORT"
log "Python UDP server is ready."

# 2) Start Weft Proxy
PROXY_LISTEN_PORT=$(find_free_port)
PROXY_LOG="$LOGDIR/proxy.log"
TARGET_URL="udp://127.0.0.1:$PY_PORT"

log "Starting weft proxy on port $PROXY_LISTEN_PORT, targeting $TARGET_URL..."
"$WEFT_BIN" proxy --verbose "${PROTO}://127.0.0.1:$PY_PORT" "${PROTO}://127.0.0.1:$PROXY_LISTEN_PORT" >"$PROXY_LOG" 2>&1 &
pids+=($!)

wait_for_port "$PROXY_LISTEN_PORT"

# 3) Verify UDP Access through Proxy
log "Attempting to connect to proxied service at udp://127.0.0.1:$PROXY_LISTEN_PORT..."
set +e
NC_OUTPUT=""
for i in $(seq 1 10); do
    NC_OUTPUT=$(echo "hello" | nc -u -w 1 127.0.0.1 "$PROXY_LISTEN_PORT")
    NC_EXIT=$?
    if echo "$NC_OUTPUT" | grep -q "$RESPONSE"; then
        break
    fi
    sleep 0.5
done
set -e

echo "nc exit: $NC_EXIT"
echo "nc output: $NC_OUTPUT"

if echo "$NC_OUTPUT" | grep -q "$RESPONSE"; then
    log "SUCCESS: received expected response from python UDP server over proxy."
    RESULT=0
else
    log "FAIL: did not receive expected response over proxy."
    log "-----"
    echo "proxy log -----"
    cat "$PROXY_LOG"
    log "-----"
    echo "python UDP server log -----"
    cat "$PY_LOG"
    RESULT=3
fi

exit "$RESULT"
