#!/usr/bin/env bash
# test/test_billing_reporting_no_double_count.sh
# Purpose: Verify that traffic is not double-counted by usage reports.
# This test verifies that the bytes reported match the actual bytes transferred,
# not more (which would indicate double-counting).

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

SHUTDOWN_WAIT=1

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Mock Usage Reporting Server that collects ALL reports
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

# 2) Start Target HTTP Server that serves a known-size response
TARGET_PORT=$(find_free_port)
TARGET_LOG="$LOGDIR/target.log"

# Create a file with exactly 10KB of data (known size)
RESPONSE_SIZE=10240
dd if=/dev/zero bs=1 count=$RESPONSE_SIZE 2>/dev/null | tr '\0' 'X' > "$LOGDIR/data.txt"

log "Starting target http server on port $TARGET_PORT..."
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
TUNNEL_NAME="no-double-count-test"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_PORT}"
LOCAL_URL="http://127.0.0.1:${TARGET_PORT}"
REMOTE_URL="http://127.0.0.1:${REMOTE_PORT}"

log "Starting weft tunnel..."
"$WEFT_BIN" tunnel --verbose --tunnel-name "$TUNNEL_NAME" "$WEFT_URL" "$LOCAL_URL" "$REMOTE_URL" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!
pids+=($TUNNEL_PID)

wait_for_port "$REMOTE_PORT"

# 5) Clear any initial usage reports
rm -f "$REPORT_FILE"

# 6) Make multiple requests to accumulate bytes
# This ensures we test the byte counting across multiple requests
log "Making 5 requests of 10KB each..."
for i in $(seq 1 5); do
    curl -s "http://127.0.0.1:$REMOTE_PORT/data.txt" > /dev/null
    log "Request $i completed"
done

# Total expected response data: 5 * 10KB = 51200 bytes (not counting HTTP headers)
EXPECTED_RESPONSE_BYTES=$((5 * RESPONSE_SIZE))

# 7) Gracefully Shutdown Tunnel to get final report
log "Stopping tunnel (sending SIGTERM to $TUNNEL_PID)..."
kill -TERM "$TUNNEL_PID"
wait "$TUNNEL_PID" || true

# Wait for the server to process the shutdown and send the report
sleep 2

# 8) Analyze usage reports for double-counting
log "Checking usage reports for double-counting..."
if [ ! -f "$REPORT_FILE" ]; then
    log "FAIL: No report file created."
    exit 5
fi

cat "$REPORT_FILE"

# Python script to analyze reports for double-counting
cat <<EOF > "$LOGDIR/analyze_reports.py"
import json
import sys

report_file = sys.argv[1]
tunnel_name = sys.argv[2]
expected_response_bytes = int(sys.argv[3])

reports = []
with open(report_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                reports.append(json.loads(line))
            except json.JSONDecodeError:
                pass

print(f"Found {len(reports)} reports")

# Collect bytes_tx (server -> client, i.e., responses) from all reports for the tunnel
bytes_tx_total = 0
bytes_rx_total = 0
for report in reports:
    for tunnel in report.get('tunnels', []):
        if tunnel.get('tunnel_name') == tunnel_name:
            tx = tunnel.get('bytes_tx', 0)
            rx = tunnel.get('bytes_rx', 0)
            bytes_tx_total += tx
            bytes_rx_total += rx
            print(f"Report: bytes_tx={tx}, bytes_rx={rx}")

if bytes_tx_total == 0 and bytes_rx_total == 0:
    print(f"FAIL: No usage data found for tunnel {tunnel_name}")
    sys.exit(1)

print(f"Total bytes_tx across all reports: {bytes_tx_total}")
print(f"Total bytes_rx across all reports: {bytes_rx_total}")
print(f"Expected response bytes (data only): {expected_response_bytes}")

# Check for double-counting:
# - bytes_tx includes HTTP headers + response body
# - If double-counted, bytes_tx would be roughly 2x expected or more
# - Allow reasonable overhead for HTTP headers (~500-1000 bytes per request)
# - With 5 requests, header overhead is roughly 2500-5000 bytes

min_expected = expected_response_bytes  # At least the raw data
max_expected = expected_response_bytes * 2  # Double would indicate a problem

# Key check: bytes_tx should be close to expected, not significantly more
if bytes_tx_total > max_expected:
    print(f"FAIL: bytes_tx ({bytes_tx_total}) exceeds 2x expected ({max_expected})")
    print("This suggests double-counting may be occurring!")
    sys.exit(2)

if bytes_tx_total < min_expected:
    print(f"FAIL: bytes_tx ({bytes_tx_total}) is less than expected response data ({min_expected})")
    print("Some data may not have been counted.")
    sys.exit(3)

# Additional check: verify bytes are not being double-counted within a single report
# by checking that the reported bytes are reasonable for the actual data transferred
ratio = bytes_tx_total / expected_response_bytes
print(f"Ratio of reported to expected bytes: {ratio:.2f}")

if ratio > 1.5:
    print(f"WARNING: Ratio is higher than expected ({ratio:.2f}), investigating...")
    # This might indicate some double-counting, but could also be due to headers
    # For 5 small requests, headers shouldn't add more than 50%
    if ratio > 2.0:
        print("FAIL: Ratio exceeds 2.0, likely double-counting!")
        sys.exit(4)

print(f"SUCCESS: bytes_tx ({bytes_tx_total}) is within expected range")
print("No double-counting detected.")
sys.exit(0)
EOF

log "Running analysis..."
if python3 "$LOGDIR/analyze_reports.py" "$REPORT_FILE" "$TUNNEL_NAME" "$EXPECTED_RESPONSE_BYTES"; then
    log "SUCCESS: Traffic is not double-counted"
    RESULT=0
else
    log "FAIL: Double-counting or other issue detected"
    RESULT=3
fi

exit "$RESULT"

