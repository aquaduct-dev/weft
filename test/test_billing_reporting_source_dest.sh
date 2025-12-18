#!/usr/bin/env bash
# test/test-billing-reporting-source-dest.sh
# Purpose: Verify that the weft server sends usage reports containing
# Source and Destination fields when a tunnel shuts down.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

SHUTDOWN_WAIT=1

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Mock Usage Reporting Server
REPORT_PORT=$(find_free_port)
REPORT_FILE="$LOGDIR/usage.json"
REPORT_LOG="$LOGDIR/report_server.log"

cat <<EOF > "$LOGDIR/mock_report_server.py"
import http.server
import sys

port = int(sys.argv[1])
outfile = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        with open(outfile, "ab") as f:
            f.write(body)
            f.write(b"\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass

print(f"Starting mock reporting server on {port}")
http.server.HTTPServer(("", port), Handler).serve_forever()
EOF

log "Starting mock reporting server on port $REPORT_PORT..."
python3 "$LOGDIR/mock_report_server.py" "$REPORT_PORT" "$REPORT_FILE" >"$REPORT_LOG" 2>&1 &
pids+=($!)
wait_for_port "$REPORT_PORT"

# 2) Start Python HTTP Server (Target)
TARGET_PORT=$(find_free_port)
TARGET_LOG="$LOGDIR/target.log"
echo "hello-usage-tracking" > "$LOGDIR/index.html"

log "Starting target http.server on port $TARGET_PORT..."
python3 -m http.server "$TARGET_PORT" --directory "$LOGDIR" >"$TARGET_LOG" 2>&1 &
pids+=($!)
wait_for_port "$TARGET_PORT"

# 3) Start Weft Server with usage reporting enabled
SERVER_PORT=$(find_free_port)
SERVER_LOG="$LOGDIR/server.log"
SECRET_FILE="$LOGDIR/secret"
REPORT_URL="http://127.0.0.1:$REPORT_PORT/report"

log "Starting weft server on port $SERVER_PORT with usage reporting to $REPORT_URL..."
"$WEFT_BIN" server --verbose --port "$SERVER_PORT" --secret-file "$SECRET_FILE" --usage-reporting-url "$REPORT_URL" >"$SERVER_LOG" 2>&1 &
pids+=($!)

# Wait for secret file
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
log "Found connection secret."

# 4) Start Weft Tunnel
REMOTE_PORT=$(find_free_port)
TUNNEL_LOG="$LOGDIR/tunnel.log"
TUNNEL_NAME="billing-test-tunnel"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_PORT}"
LOCAL_URL="http://127.0.0.1:${TARGET_PORT}"
REMOTE_URL="http://127.0.0.1:${REMOTE_PORT}"

log "Starting weft tunnel..."
"$WEFT_BIN" tunnel --verbose --tunnel-name "$TUNNEL_NAME" "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!
pids+=($TUNNEL_PID)

wait_for_port "$REMOTE_PORT"

# 5) Generate Traffic
echo "Generating traffic..."
curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null
curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null
curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null

# 6) Gracefully Shutdown Tunnel
log "Stopping tunnel (sending SIGTERM to $TUNNEL_PID)..."
kill -TERM "$TUNNEL_PID"

# Remove TUNNEL_PID from pids array so cleanup doesn't try to kill it again (though kill is safe)
# But wait for it to exit to ensure it had time to send the shutdown request
wait "$TUNNEL_PID" || true

# Wait a moment for the server to process the shutdown and send the report
sleep 2

# 7) Verify Usage Report
log "Checking usage report..."
if [ -f "$REPORT_FILE" ]; then
    cat "$REPORT_FILE"
    
    # Check for Source (Local URL)
    # Note: local URL in connect request is "http://127.0.0.1:TARGET_PORT"
    EXPECTED_SOURCE="http://127.0.0.1:${TARGET_PORT}"
    if grep -qF "\"source\":\"$EXPECTED_SOURCE\"" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained correct source '$EXPECTED_SOURCE'"
    else
        log "FAIL: Usage report did NOT contain correct source '$EXPECTED_SOURCE'"
        RESULT=3
    fi

    # Check for Destination (Remote URL)
    # Note: destination URL stored in peer is "http://127.0.0.1:REMOTE_PORT"
    EXPECTED_DEST="http://127.0.0.1:${REMOTE_PORT}"
    if grep -qF "\"destination\":\"$EXPECTED_DEST\"" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained correct destination '$EXPECTED_DEST'"
    else
        log "FAIL: Usage report did NOT contain correct destination '$EXPECTED_DEST'"
        RESULT=3
    fi

    if [ "$RESULT" -eq 1 ]; then
        RESULT=0
    fi
else
    log "FAIL: Report file not created."
    RESULT=4
fi

exit "$RESULT"
