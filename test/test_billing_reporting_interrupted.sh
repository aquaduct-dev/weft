#!/usr/bin/env bash
# test/test_billing_reporting_interrupted.sh
# Purpose: Verify that data from canceled/interrupted HTTP connections is still
# reported in billing usage reports.

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

# 2) Start Slow-Responding Target HTTP Server
# This server streams data slowly to simulate a large download that can be interrupted
TARGET_PORT=$(find_free_port)
TARGET_LOG="$LOGDIR/target.log"

cat <<EOF > "$LOGDIR/slow_server.py"
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
        
        # Stream data slowly - send chunks with delays
        chunk = b"X" * 1024  # 1KB chunks
        for i in range(100):  # Would send 100KB total if not interrupted
            try:
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(0.1)  # 100ms between chunks
            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected - this is expected for interrupted connections
                break
        
        # Send final chunk (may not reach here if interrupted)
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
python3 "$LOGDIR/slow_server.py" "$TARGET_PORT" >"$TARGET_LOG" 2>&1 &
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
TUNNEL_NAME="interrupted-test-tunnel"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_PORT}"
LOCAL_URL="http://127.0.0.1:${TARGET_PORT}"
REMOTE_URL="http://127.0.0.1:${REMOTE_PORT}"

log "Starting weft tunnel..."
"$WEFT_BIN" tunnel --verbose --tunnel-name "$TUNNEL_NAME" "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!
pids+=($TUNNEL_PID)

wait_for_port "$REMOTE_PORT"

# 5) Make request and interrupt it mid-transfer
log "Starting HTTP request that will be interrupted..."
# timeout will kill the request after 0.5 seconds, while the server would need ~10 seconds to complete
timeout 0.5 curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null 2>&1 || true

# Give a moment for any cleanup
sleep 0.5

# 6) Gracefully Shutdown Tunnel
log "Stopping tunnel (sending SIGTERM to $TUNNEL_PID)..."
kill -TERM "$TUNNEL_PID"
wait "$TUNNEL_PID" || true

# Wait for the server to process the shutdown and send the report
sleep 2

# 7) Verify Usage Report
log "Checking usage report..."
if [ -f "$REPORT_FILE" ]; then
    cat "$REPORT_FILE"
    
    # Check that report contains tunnel name
    if grep -q "$TUNNEL_NAME" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained tunnel name '$TUNNEL_NAME'"
        
        # Check that BytesTx or BytesRx is non-zero (proving partial data was counted)
        # The JSON format has "bytes_tx" and "bytes_rx" fields
        if grep -qE '"bytes_(tx|rx)":[1-9]' "$REPORT_FILE"; then
            log "SUCCESS: Usage report shows non-zero bytes transferred"
            RESULT=0
        else
            # Also check for older field names or integer values > 0
            if grep -qE '(BytesTx|BytesRx|bytes_tx|bytes_rx)"?:[[:space:]]*[1-9]' "$REPORT_FILE"; then
                log "SUCCESS: Usage report shows non-zero bytes transferred"
                RESULT=0
            else
                log "FAIL: Usage report shows zero bytes transferred - interrupted data was NOT counted"
                RESULT=3
            fi
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
