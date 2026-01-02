#!/usr/bin/env bash
# test/test_billing_reporting_no_double_count.sh
# Purpose: Verify that traffic is not double-counted by usage reports.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Mock Usage Reporting Server
start_mock_report_server

# 2) Start Target HTTP Server with known-size response
RESPONSE_SIZE=10240
dd if=/dev/zero bs=1 count=$RESPONSE_SIZE 2>/dev/null | tr '\0' 'X' > "$LOGDIR/data.txt"
start_target_http_server "hello"

# 3) Start Weft Server with usage reporting enabled
start_weft_server_with_reporting

# 4) Start Weft Tunnel
REMOTE_PORT=$(find_free_port)
TUNNEL_NAME="no-double-count-test"
LOCAL_URL="http://127.0.0.1:${TARGET_PORT}"
REMOTE_URL="http://127.0.0.1:${REMOTE_PORT}"

start_weft_tunnel "$TUNNEL_NAME" "$LOCAL_URL" "$REMOTE_URL"

# 5) Clear any initial usage reports
rm -f "$REPORT_FILE"

# 6) Make multiple requests
log "Making 5 requests of 10KB each..."
for i in $(seq 1 5); do
    curl -s "http://127.0.0.1:$REMOTE_PORT/data.txt" > /dev/null
    log "Request $i completed"
done

EXPECTED_RESPONSE_BYTES=$((5 * RESPONSE_SIZE))

# 7) Gracefully Shutdown Tunnel
stop_tunnel_gracefully "$TUNNEL_PID"

# 8) Analyze usage reports for double-counting
log "Checking usage reports for double-counting..."
if [ ! -f "$REPORT_FILE" ]; then
    log "FAIL: No report file created."
    exit 5
fi

cat "$REPORT_FILE"

# Python script to analyze reports
cat <<'EOF' > "$LOGDIR/analyze_reports.py"
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

print(f"Total bytes_tx: {bytes_tx_total}, bytes_rx: {bytes_rx_total}")
print(f"Expected response bytes: {expected_response_bytes}")

max_expected = expected_response_bytes * 2
if bytes_tx_total > max_expected:
    print(f"FAIL: bytes_tx ({bytes_tx_total}) exceeds 2x expected ({max_expected})")
    sys.exit(2)

if bytes_tx_total < expected_response_bytes:
    print(f"FAIL: bytes_tx ({bytes_tx_total}) is less than expected ({expected_response_bytes})")
    sys.exit(3)

ratio = bytes_tx_total / expected_response_bytes
print(f"Ratio: {ratio:.2f}")
if ratio > 2.0:
    print("FAIL: Ratio exceeds 2.0, likely double-counting!")
    sys.exit(4)

print("SUCCESS: No double-counting detected.")
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
