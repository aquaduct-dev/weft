#!/usr/bin/env bash
# test/test-tcp.sh
# Purpose: end-to-end script that uses the compiled weft CLI to:
#  1) start a simple python TCP server
#  2) start the weft server
#  3) start a weft tunnel that exposes the python server over the weft server
#  4) verify TCP access works over the tunnel
#
# Notes:
# - Assumes the weft CLI binary is built and available as `./weft` by default.
#   You can override with WEFT_BIN environment variable.
# - Uses ports that are unlikely to conflict with system services.
# - Emits verbose logging to help debug failures.
#
# Exit codes:
#  0 = success (tcp reached over tunnel)
#  non-zero = failure

set -euo pipefail
IFS=$'\n\t'

# Configuration
WEFT_BIN=${WEFT_BIN:-./weft}   # path to compiled binary (allow override)
PY_PORT=18080                  # local python server port
REMOTE_PORT=29090              # remote port the tunnel will request on server (public facing)
SERVER_BIND_PORT=9092          # server's wireguard/listen port used by server CLI
LOGDIR=$(mktemp -d /tmp/weft-test-XXXX)
PY_LOG="$LOGDIR/python.log"
SERVER_LOG="$LOGDIR/server.log"
TUNNEL_LOG="$LOGDIR/tunnel.log"
SHUTDOWN_WAIT=1

trap 'echo "Test interrupted, cleaning up..."; pkill -P $$ || true; sleep 1; rm -rf "$LOGDIR"' EXIT

echo "Logs will be written to $LOGDIR"

# 1) Start a simple Python TCP echo server that replies with a fixed message.
cat > "$LOGDIR/py_server.py" <<'PY'
import socket
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"python server listening on {HOST}:{PORT}", flush=True)
    conn, addr = s.accept()
    with conn:
        print("connected by", addr, flush=True)
        data = conn.recv(1024)
        if not data:
            sys.exit(0)
        conn.sendall(b"hello-from-py-server")
PY

echo "Starting python TCP server on port $PY_PORT..."
python3 "$LOGDIR/py_server.py" "$PY_PORT" >"$PY_LOG" 2>&1 &
PY_PID=$!
sleep 0.2

# 2) Start the weft server (uses the same binary as CLI subcommand `server`)
echo "Starting weft server..."
"$WEFT_BIN" server --verbose --port "$SERVER_BIND_PORT" &>"$SERVER_LOG" &
SERVER_PID=$!

# Wait for the server to print the connection secret (with timeout)
TIMEOUT=5
SECS=0
CONN_SECRET=""
while [ $SECS -lt $TIMEOUT ]; do
  if grep -q "Connection Secret" "$SERVER_LOG"; then
    CONN_SECRET=$(grep -m1 "Connection Secret" "$SERVER_LOG" | awk -F': ' '{print $2}' || true)
    break
  fi
  sleep 1
  SECS=$((SECS+1))
done

if [ -z "$CONN_SECRET" ]; then
  echo "Failed to find connection secret in server log ($SERVER_LOG):"
  sed -n '1,200p' "$SERVER_LOG"
  kill "$SERVER_PID" || true
  kill "$PY_PID" || true
  exit 2
fi
echo "Found connection secret: $CONN_SECRET"

# 3) Start the weft tunnel connecting to the local python server and requesting remote port REMOTE_PORT
# The tunnel expects weft://{connection-secret}@{server-ip}
# Since server is local in tests, we use 127.0.0.1 as server-ip
# The server control API is addressed on port 9092 per README; point the weft URL at that control port so the tunnel POSTs to /connect.
WEFT_URL="weft://:${CONN_SECRET}@127.0.0.1:9092"
LOCAL_URL="tcp://127.0.0.1:${PY_PORT}"
REMOTE_URL="tcp://127.0.0.1:${REMOTE_PORT}"

# Wait for server control port to become ready before starting tunnel (avoid race)
echo "Waiting for server control port 9092 to be ready..."
READY=0
for i in $(seq 1 10); do
  if nc -z 127.0.0.1 9092 >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done
if [ "$READY" -ne 1 ]; then
  echo "Server control port 9092 did not become ready in time; dumping server log:"
  sed -n '1,200p' "$SERVER_LOG"
  kill "$SERVER_PID" || true
  kill "$PY_PID" || true
  exit 4
fi

echo "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_URL..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!

# Give processes time to settle
sleep 1

# 4) Verify TCP can be accessed over the tunnel.
# The server, on successful connect, will listen on REMOTE_PORT on localhost (see server.Serve listening behavior).
echo "Attempting to connect to tunneled service at 127.0.0.1:$REMOTE_PORT..."
set +e
NC_OUTPUT=$(printf "ping\n" | nc -w 3 127.0.0.1 "$REMOTE_PORT" 2>&1) || NC_EXIT=$?
NC_EXIT=${NC_EXIT:-0}
set -e

echo "nc exit: $NC_EXIT"
echo "nc output:"
echo "$NC_OUTPUT"

if echo "$NC_OUTPUT" | grep -q "hello-from-py-server"; then
  echo "SUCCESS: received expected response from python server over tunnel."
  RESULT=0
else
  echo "FAIL: did not receive expected response over tunnel."
  echo "----- server log -----"
  sed -n '1,200p' "$SERVER_LOG"
  echo "----- tunnel log -----"
  sed -n '1,200p' "$TUNNEL_LOG"
  echo "----- python log -----"
  sed -n '1,200p' "$PY_LOG"
  RESULT=3
fi

# Cleanup
echo "Shutting down processes..."
kill "$TUNNEL_PID" >/dev/null 2>&1 || true
kill "$SERVER_PID" >/dev/null 2>&1 || true
kill "$PY_PID" >/dev/null 2>&1 || true
sleep "$SHUTDOWN_WAIT"

# Preserve logs on failure, remove on success
if [ "$RESULT" -eq 0 ]; then
  rm -rf "$LOGDIR"
  echo "Test passed."
else
  echo "Test failed. Logs retained at $LOGDIR"
fi

exit "$RESULT"