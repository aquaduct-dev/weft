#!/usr/bin/env bash
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# 1) Start Python HTTP Server with custom path logic
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python.log"
PY_SCRIPT="$LOGDIR/upstream.py"

cat > "$PY_SCRIPT" <<EOF
import http.server
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"UPSTREAM: {self.command} {self.path}")
        if self.path == "/create":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")

if __name__ == "__main__":
    port = int(sys.argv[1])
    server = http.server.HTTPServer(("", port), Handler)
    print(f"Upstream listening on :{port}")
    server.serve_forever()
EOF

log "Starting python upstream on port $PY_PORT..."
python3 "$PY_SCRIPT" "$PY_PORT" >"$PY_LOG" 2>&1 &
pids+=($!)
wait_for_port "$PY_PORT"

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

# 3) Start Weft Tunnel
# Mapping: http://my-app.example.com/api/v1 -> http://127.0.0.1:$PY_PORT
# We expect requests to /api/v1/create on the tunnel to go to /create on upstream
TUNNEL_BIND_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
REMOTE_HOST="my-app.example.com"
# Note: The server listens on the port specified in the remote URL.
# So we need to use a port that we can hit.
# Since we can't easily modify /etc/hosts in sandbox, we'll hit 127.0.0.1:$TUNNEL_BIND_PORT with Host header.

WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="http://127.0.0.1:${PY_PORT}"
REMOTE_URL="http://${REMOTE_HOST}:${TUNNEL_BIND_PORT}/api/v1"

wait_for_port "$SERVER_BIND_PORT"

log "Starting weft tunnel..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# 4) Verify Path Rewriting
# Wait for the VHost proxy to be ready on the server.
# The server opens TUNNEL_BIND_PORT when the tunnel connects.
wait_for_port "$TUNNEL_BIND_PORT"

log "Testing Path Rewriting..."
# Request: http://127.0.0.1:$TUNNEL_BIND_PORT/api/v1/create
# Host: my-app.example.com
# Expected Upstream Path: /create

RESPONSE=$(curl -s -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/api/v1/create")
log "Got response: $RESPONSE"

if [ "$RESPONSE" == "ok" ]; then
    log "SUCCESS: Path rewriting worked!"
    RESULT=0
else
    log "FAILURE: Expected 'ok', got '$RESPONSE'"
    RESULT=1
fi

exit "$RESULT"