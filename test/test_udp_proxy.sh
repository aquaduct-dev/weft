#!/usr/bin/env bash
# test/test_udp_proxy.sh
# Purpose: end-to-end script that uses the compiled weft CLI to:
#  1) start a simple nc udp server on a free port
#  2) start the weft proxy that proxies to the nc server
#  3) verify UDP access works over the proxy
#
PROTO=${PROTO:-udp}

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
        if nc -z -u "$host" "$port" >/dev/null 2>&1;
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

echo "Starting python UDP server on port $PY_PORT..."
python3 "$LOGDIR/udp_server.py" "$PY_PORT" "$RESPONSE" >"$PY_LOG" 2>&1 &
pids+=($!)
wait_for_port "$PY_PORT"
echo "Python UDP server is ready."

# 2) Start Weft Proxy
PROXY_LISTEN_PORT=$(find_free_port)
PROXY_LOG="$LOGDIR/proxy.log"
TARGET_URL="udp://127.0.0.1:$PY_PORT"

echo "Starting weft proxy on port $PROXY_LISTEN_PORT, targeting $TARGET_URL..."
"$WEFT_BIN" proxy --verbose "${PROTO}://127.0.0.1:$PROXY_LISTEN_PORT" "${PROTO}://127.0.0.1:$PY_PORT" >"$PROXY_LOG" 2>&1 &
pids+=($!)

wait_for_port "$PROXY_LISTEN_PORT"

# 3) Verify UDP Access through Proxy
echo "Attempting to connect to proxied service at udp://127.0.0.1:$PROXY_LISTEN_PORT..."
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
    echo "SUCCESS: received expected response from python UDP server over proxy."
    RESULT=0
else
    echo "FAIL: did not receive expected response over proxy."
    echo "-----"
    echo "proxy log -----"
    cat "$PROXY_LOG"
    echo "-----"
    echo "python UDP server log -----"
    cat "$PY_LOG"
    RESULT=3
fi

exit "$RESULT"
