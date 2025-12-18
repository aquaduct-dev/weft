#!/usr/bin/env bash
# test/test_https_tunnel.sh
# Purpose: end-to-end HTTPS tunnel test that is self-contained (no dependency
# on test_tcp_tunnel.sh).

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

# --- Setup ---
TMPDIR="$(mktemp -d)"

log "Logs will be written to $LOGDIR"

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
 
log "Starting python http.server on port $PY_PORT..."
python3 "$LOGDIR/serve_http.py" "$PY_PORT" >"$PY_LOG" 2>&1 &
pids+=($!)


# --- 3) Start weft server ---
SERVER_BIND_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"

log "Starting weft server on port $SERVER_BIND_PORT..."
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
log "Found connection secret: $CONN_SECRET"

# --- 4) Start weft tunnel ---
REMOTE_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="http://127.0.0.1:${PY_PORT}"
REMOTE_URL="https://localhost:${REMOTE_PORT}"
 
wait_for_port "$SERVER_BIND_PORT"

 
log "Starting weft tunnel to expose $LOCAL_URL at remote $REMOTE_URL..."
# Pass certificate data as flags to the tunnel so the remote endpoint presents TLS
# The tunnel command is expected to accept --tls-cert and --tls-key flags.
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" --tls-cert "$CERT" --tls-key "$KEY" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# --- 5) Verify HTTPS Access ---
# wait for remote port to be open (tunnel)
wait_for_port "$REMOTE_PORT"
wait_for_port "$PY_PORT" || { cat "$PY_LOG"; exit 5; }
log "Python http.server is ready."

log "Attempting to connect to tunneled service at $REMOTE_URL..."
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
  log "SUCCESS: received expected response from python https server over tunnel."
  RESULT=0
else
  log "FAIL: did not receive expected response over tunnel."
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