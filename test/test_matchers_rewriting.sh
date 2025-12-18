#!/usr/bin/env bash
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# 1) Start Python HTTP Server with custom match logic
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python.log"
PY_SCRIPT="$LOGDIR/upstream.py"

cat > "$PY_SCRIPT" <<EOF
import http.server
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"UPSTREAM: {self.command} {self.path}")
        if self.path.startswith("/api/v1/create"):
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

# 3) Start Weft Tunnel with Query Matcher
# Mapping: http://my-app.example.com?token=secret -> http://127.0.0.1:$PY_PORT
# We expect requests to /api/v1/create on the tunnel to go to upstream only if ?token=secret is present
TUNNEL_BIND_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
REMOTE_HOST="my-app.example.com"

WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
LOCAL_URL="http://127.0.0.1:${PY_PORT}"
REMOTE_URL="http://${REMOTE_HOST}:${TUNNEL_BIND_PORT}?token=secret"

wait_for_port "$SERVER_BIND_PORT"

log "Starting weft tunnel..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# 4) Verify Query Matcher
wait_for_port "$TUNNEL_BIND_PORT"

log "Testing Query Matcher..."

# Valid request
RESPONSE_VALID=$(curl -s -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/api/v1/create?token=secret")
echo "Got valid response: $RESPONSE_VALID"

# Invalid request (wrong token)
RESPONSE_INVALID=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: ${REMOTE_HOST}" "http://127.0.0.1:${TUNNEL_BIND_PORT}/api/v1/create?token=wrong")
echo "Got invalid response code: $RESPONSE_INVALID"

if [ "$RESPONSE_VALID" == "ok" ] && [ "$RESPONSE_INVALID" == "404" ]; then
    log "SUCCESS: Query matcher worked!"
    RESULT=0
else
    log "FAILURE: Validation failed."
    RESULT=1
fi

exit "$RESULT"
