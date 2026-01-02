#!/usr/bin/env bash
# test/test_billing_reporting_interrupted.sh
# Purpose: Verify that data from canceled/interrupted HTTP connections is still
# reported in billing usage reports.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Mock Usage Reporting Server
start_mock_report_server

# 2) Start Slow-Responding Target HTTP Server (unique to this test)
TARGET_PORT=$(find_free_port)

cat <<'EOF' > "$LOGDIR/slow_server.py"
import http.server
import sys
import time

port = int(sys.argv[1])

class SlowHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        
        chunk = b"X" * 1024  # 1KB chunks
        for i in range(100):  # Would send 100KB total if not interrupted
            try:
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError):
                break
        
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format, *args):
        pass

print(f"Starting slow server on {port}")
http.server.HTTPServer(("", port), SlowHandler).serve_forever()
EOF

log "Starting slow target http server on port $TARGET_PORT..."
python3 "$LOGDIR/slow_server.py" "$TARGET_PORT" >"$LOGDIR/target.log" 2>&1 &
pids+=($!)
wait_for_port "$TARGET_PORT"

# 3) Start Weft Server with usage reporting enabled
start_weft_server_with_reporting

# 4) Start Weft Tunnel
REMOTE_PORT=$(find_free_port)
TUNNEL_NAME="interrupted-test-tunnel"
LOCAL_URL="http://127.0.0.1:${TARGET_PORT}"
REMOTE_URL="http://127.0.0.1:${REMOTE_PORT}"

start_weft_tunnel "$TUNNEL_NAME" "$LOCAL_URL" "$REMOTE_URL"

# 5) Make request and interrupt it mid-transfer
log "Starting HTTP request that will be interrupted..."
timeout 0.5 curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null 2>&1 || true
sleep 0.5

# 6) Gracefully Shutdown Tunnel
stop_tunnel_gracefully "$TUNNEL_PID"

# 7) Verify Usage Report
log "Checking usage report..."
if [ -f "$REPORT_FILE" ]; then
    cat "$REPORT_FILE"
    
    if grep -q "$TUNNEL_NAME" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained tunnel name '$TUNNEL_NAME'"
        
        # Check that bytes were counted (proving partial data was reported)
        if grep -qE '(bytes_tx|bytes_rx)"?:[[:space:]]*[1-9]' "$REPORT_FILE"; then
            log "SUCCESS: Usage report shows non-zero bytes transferred"
            RESULT=0
        else
            log "FAIL: Usage report shows zero bytes transferred - interrupted data was NOT counted"
            RESULT=3
        fi
    else
        log "FAIL: Usage report did not contain tunnel name '$TUNNEL_NAME'"
        RESULT=4
    fi
else
    log "FAIL: Report file not created."
    RESULT=5
fi

exit "$RESULT"
