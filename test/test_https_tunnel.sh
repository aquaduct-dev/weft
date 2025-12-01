#!/usr/bin/env bash
# test/test_https_tunnel.sh
# Purpose: end-to-end HTTPS tunnel test that is self-contained (no dependency
# on test_tcp_tunnel.sh). It:
#  1) generates a temporary self-signed cert/key
#  2) starts a simple python HTTPS server on a free port using the generated cert
#  3) starts the weft server on a free port
#  4) starts a weft tunnel that exposes the python server over the weft server
#  5) verifies HTTPS access works over the tunnel
#
# Notes:
# - Assumes the weft CLI binary is built and available as "./weft" by default.
#   You can override with WEFT_BIN environment variable.
# - Uses dynamic ports to avoid conflicts.
# - Emits verbose logging to help debug failures.
#
# Exit codes:
#  0 = success
#  non-zero = failure

set -uo pipefail
IFS=$'\n\t'

# --- Helpers ---
log() {
  echo "test_https_tunnel: $*" >&2
}

cleanup() {
  if [[ "${RESULT:-1}" -ne 0 ]]; then
    echo "Test failed. Logs retained at $LOGDIR"
  else
    rm -rf "$LOGDIR"
    echo "Test passed."
  fi

  # Kill all tracked processes
  for pid in "${pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done

  if [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# --- Setup ---
# Resolve the weft binary:
# - honor WEFT_BIN if provided
# - otherwise prefer ./weft (convenience for local runs)
# - otherwise try to locate the binary in Bazel runfiles using RUNFILES_DIR or
#   RUNFILES_MANIFEST_FILE so the test works under Bazel sh_test.
# --- Setup ---
LOGDIR="$(mktemp -d /tmp/weft-test-XXXX)"
TMPDIR="$(mktemp -d)"
RESULT=1
pids=()
WEFT_BIN=$(find . | grep -e "/weft$")


echo "Logs will be written to $LOGDIR"
# --- Port helpers ---
find_free_port() {
  python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("",0))
print(s.getsockname()[1])
s.close()
PY
}

wait_for_port() {
  local port=$1
  local host=${2:-127.0.0.1}
  local timeout=${3:-10}
  echo "Waiting for $host:$port to be open..."
  for i in $(seq 1 "$timeout"); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      echo "$host:$port is open."
      return 0
    fi
    sleep 0.5
  done
  echo "Timed out waiting for $host:$port."
  return 1
}

# --- 1) Generate self-signed cert/key ---
CERT="$TMPDIR/cert.pem"
KEY="$TMPDIR/key.pem"

log "Generating self-signed certificate (valid for 1 day)"
if ! command -v openssl >/dev/null 2>&1; then
  log "openssl is required for this test"
  exit 3
fi

openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -subj "/CN=localhost" \
  -keyout "$KEY" -out "$CERT" >/dev/null 2>&1

if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
  log "Certificate generation failed"
  exit 4
fi

# Export cert paths for the weft tunnel to use if it supports them
export HTTPS_CERT="$CERT"
export HTTPS_KEY="$KEY"

# --- 2) Start plain HTTP server (we'll tunnel it and present TLS on the remote) ---
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python.log"
echo "hello-from-http-server" > "$LOGDIR/index.html"
 
# Start a small HTTP server that returns a fixed response
cat > "$LOGDIR/serve_http.py" <<PYCODE
import http.server, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello-from-http-server")
if __name__ == "__main__":
    port = int(sys.argv[1])
    HTTPServer(('127.0.0.1', port), Handler).serve_forever()
PYCODE
 
echo "Starting python http.server on port $PY_PORT..."
python3 "$LOGDIR/serve_http.py" "$PY_PORT" >"$PY_LOG" 2>&1 &
pids+=($!)


# --- 3) Start weft server ---
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

echo "Starting weft server on port $SERVER_BIND_PORT..."
"$WEFT_BIN" server --verbose --port "$SERVER_BIND_PORT" --secret-file "$SECRET_FILE"  >"$SERVER_LOG" 2>&1 &
pids+=($!)

# Wait for the secret file to be created
for i in $(seq 1 10); do
  if [ -f "$SECRET_FILE" ]; then break; fi
  sleep 0.5
done

if [ ! -f "$SECRET_FILE" ]; then
  log "Failed to find secret file."
  cat "$SERVER_LOG"
  exit 6
fi

CONN_SECRET=$(cat "$SECRET_FILE" | tr -d '\n')
echo "Found connection secret: $CONN_SECRET"

# --- 4) Start weft tunnel ---
REMOTE_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="http://127.0.0.1:${PY_PORT}"
REMOTE_URL="https://localhost:${REMOTE_PORT}"
 
wait_for_port "$SERVER_BIND_PORT"

 
echo "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_URL..."
# Pass certificate data as flags to the tunnel so the remote endpoint presents TLS
# The tunnel command is expected to accept --tls-cert and --tls-key flags.
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" --tls-cert "$CERT" --tls-key "$KEY" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# --- 5) Verify HTTPS Access ---
# wait for remote port to be open (tunnel)
wait_for_port "$REMOTE_PORT"
wait_for_port "$PY_PORT" || { cat "$PY_LOG"; exit 5; }
echo "Python http.server is ready."

echo "Attempting to connect to tunneled service at $REMOTE_URL..."
set +e
CURL_EXIT=7
CURL_OUTPUT=""
for i in $(seq 1 10); do
  # Insecure (-k) because we use a self-signed cert
  CURL_OUTPUT=$(curl -ks "${REMOTE_URL}")
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
  echo "SUCCESS: received expected response from python https server over tunnel."
  RESULT=0
else
  echo "FAIL: did not receive expected response over tunnel."
  echo "-----"
  echo "server log -----"
  cat "$SERVER_LOG"
  echo "-----"
  echo "tunnel log -----"
  cat "$TUNNEL_LOG"
  echo "-----"
  echo "python log -----"
  cat "$PY_LOG"
  RESULT=3
fi

exit "$RESULT"