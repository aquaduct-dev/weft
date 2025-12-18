#!/usr/bin/env bash
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# 1) Start Python HTTP Server that prints received headers
PY_PORT=$(find_free_port)
PY_LOG="$LOGDIR/python.log"
PY_SCRIPT="$LOGDIR/upstream.py"

cat > "$PY_SCRIPT" <<EOF
import http.server
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"UPSTREAM: {self.command} {self.path}")
        print("UPSTREAM_HEADERS:")
        for k, v in self.headers.items():
            print(f"{k}: {v}")
        sys.stdout.flush()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

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

# 3) Start Weft Tunnel with Header Modifiers
# Modifiers: Forwarded=true (set), X-Forwarded-For=!del (remove), Authorization=+auth (add if missing)
TUNNEL_BIND_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
REMOTE_HOST="my-app.example.com"

WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_BIND_PORT}"
# Matchers are in dstURL fragment? No, modifiers are in srcURL fragment as per my implementation in proxy.go
LOCAL_URL="http://127.0.0.1:${PY_PORT}/#Forwarded=true&X-Forwarded-For=!del&Authorization=+auth"
REMOTE_URL="http://${REMOTE_HOST}:${TUNNEL_BIND_PORT}"

wait_for_port "$SERVER_BIND_PORT"

log "Starting weft tunnel..."
"$WEFT_BIN" tunnel --verbose "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
pids+=($!)

# 4) Verify Header Modifiers
wait_for_port "$TUNNEL_BIND_PORT"

log "Testing Header Modifiers..."

# Request with X-Forwarded-For (should be deleted)
# Request WITHOUT Authorization (should be added as 'auth')
curl -s -H "Host: ${REMOTE_HOST}" -H "X-Forwarded-For: 1.2.3.4" "http://127.0.0.1:${TUNNEL_BIND_PORT}/test" > /dev/null

sleep 1

log "Checking logs for modified headers..."
if grep -q "Forwarded: true" "$PY_LOG" && \
   ! grep -q "X-Forwarded-For: 1.2.3.4" "$PY_LOG" && \
   grep -q "Authorization: auth" "$PY_LOG"; then
    log "SUCCESS: Header modifiers worked!"
    RESULT=0
else
    log "FAILURE: Header modifiers did not work as expected."
    RESULT=1
fi

exit "$RESULT"
