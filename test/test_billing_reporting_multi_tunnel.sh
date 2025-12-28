#!/usr/bin/env bash
# test/test_billing_reporting_multi_tunnel.sh
# Purpose: Verify that the weft server correctly reports usage for multiple
# tunnels from the same client when they shut down.

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

# 2) Start Two Python HTTP Servers (Targets for each tunnel)
TARGET_PORT1=$(find_free_port)
TARGET_LOG1="$LOGDIR/target1.log"
mkdir -p "$LOGDIR/target1"
echo "hello-from-target1" > "$LOGDIR/target1/index.html"

log "Starting target http.server 1 on port $TARGET_PORT1..."
python3 -m http.server "$TARGET_PORT1" --directory "$LOGDIR/target1" >"$TARGET_LOG1" 2>&1 &
pids+=($!)
wait_for_port "$TARGET_PORT1"

TARGET_PORT2=$(find_free_port)
TARGET_LOG2="$LOGDIR/target2.log"
mkdir -p "$LOGDIR/target2"
echo "hello-from-target2" > "$LOGDIR/target2/index.html"

log "Starting target http.server 2 on port $TARGET_PORT2..."
python3 -m http.server "$TARGET_PORT2" --directory "$LOGDIR/target2" >"$TARGET_LOG2" 2>&1 &
pids+=($!)
wait_for_port "$TARGET_PORT2"

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

# 4) Start First Weft Tunnel
REMOTE_PORT1=$(find_free_port)
TUNNEL_LOG1="$LOGDIR/tunnel1.log"
TUNNEL_NAME1="billing-test-tunnel-1"
WEFT_URL="weft://${CONN_SECRET}@127.0.0.1:${SERVER_PORT}"
LOCAL_URL1="http://127.0.0.1:${TARGET_PORT1}"
REMOTE_URL1="http://127.0.0.1:${REMOTE_PORT1}"

log "Starting weft tunnel 1..."
"$WEFT_BIN" tunnel --verbose --tunnel-name "$TUNNEL_NAME1" "$WEFT_URL" "$LOCAL_URL1" "$REMOTE_URL1" >"$TUNNEL_LOG1" 2>&1 &
TUNNEL_PID1=$!
pids+=($TUNNEL_PID1)

wait_for_port "$REMOTE_PORT1"

# 5) Start Second Weft Tunnel
REMOTE_PORT2=$(find_free_port)
TUNNEL_LOG2="$LOGDIR/tunnel2.log"
TUNNEL_NAME2="billing-test-tunnel-2"
LOCAL_URL2="http://127.0.0.1:${TARGET_PORT2}"
REMOTE_URL2="http://127.0.0.1:${REMOTE_PORT2}"

log "Starting weft tunnel 2..."
"$WEFT_BIN" tunnel --verbose --tunnel-name "$TUNNEL_NAME2" "$WEFT_URL" "$LOCAL_URL2" "$REMOTE_URL2" >"$TUNNEL_LOG2" 2>&1 &
TUNNEL_PID2=$!
pids+=($TUNNEL_PID2)

wait_for_port "$REMOTE_PORT2"

# 6) Generate Traffic on Both Tunnels (with timeouts to avoid hanging)
log "Generating traffic on tunnel 1..."
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT1" > /dev/null || true
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT1" > /dev/null || true

log "Generating traffic on tunnel 2..."
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT2" > /dev/null || true
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT2" > /dev/null || true
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT2" > /dev/null || true

# 7) Gracefully Shutdown Both Tunnels
log "Stopping tunnel 1 (sending SIGTERM to $TUNNEL_PID1)..."
kill -TERM "$TUNNEL_PID1"
wait "$TUNNEL_PID1" || true

log "Stopping tunnel 2 (sending SIGTERM to $TUNNEL_PID2)..."
kill -TERM "$TUNNEL_PID2"
wait "$TUNNEL_PID2" || true

# Wait a moment for the server to process the shutdowns and send reports
sleep 2

# 8) Verify Usage Reports
log "Checking usage reports..."
RESULT=0

if [ -f "$REPORT_FILE" ]; then
    cat "$REPORT_FILE"
    
    # Check for tunnel 1
    if grep -q "$TUNNEL_NAME1" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained tunnel name '$TUNNEL_NAME1'"
    else
        log "FAIL: Usage report did not contain tunnel name '$TUNNEL_NAME1'"
        RESULT=3
    fi

    # Check for tunnel 2
    if grep -q "$TUNNEL_NAME2" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained tunnel name '$TUNNEL_NAME2'"
    else
        log "FAIL: Usage report did not contain tunnel name '$TUNNEL_NAME2'"
        RESULT=3
    fi

    # Verify we got two separate reports (two lines in the file)
    REPORT_COUNT=$(wc -l < "$REPORT_FILE")
    if [ "$REPORT_COUNT" -ge 2 ]; then
        log "SUCCESS: Received $REPORT_COUNT usage reports (expected at least 2)"
    else
        log "FAIL: Only received $REPORT_COUNT usage report(s), expected at least 2"
        RESULT=3
    fi

    # Verify source/destination for tunnel 1
    EXPECTED_SOURCE1="http://127.0.0.1:${TARGET_PORT1}"
    EXPECTED_DEST1="http://127.0.0.1:${REMOTE_PORT1}"
    if grep -qF "\"source\":\"$EXPECTED_SOURCE1\"" "$REPORT_FILE"; then
        log "SUCCESS: Found correct source for tunnel 1"
    else
        log "FAIL: Missing correct source for tunnel 1: $EXPECTED_SOURCE1"
        RESULT=3
    fi
    if grep -qF "\"destination\":\"$EXPECTED_DEST1\"" "$REPORT_FILE"; then
        log "SUCCESS: Found correct destination for tunnel 1"
    else
        log "FAIL: Missing correct destination for tunnel 1: $EXPECTED_DEST1"
        RESULT=3
    fi

    # Verify source/destination for tunnel 2
    EXPECTED_SOURCE2="http://127.0.0.1:${TARGET_PORT2}"
    EXPECTED_DEST2="http://127.0.0.1:${REMOTE_PORT2}"
    if grep -qF "\"source\":\"$EXPECTED_SOURCE2\"" "$REPORT_FILE"; then
        log "SUCCESS: Found correct source for tunnel 2"
    else
        log "FAIL: Missing correct source for tunnel 2: $EXPECTED_SOURCE2"
        RESULT=3
    fi
    if grep -qF "\"destination\":\"$EXPECTED_DEST2\"" "$REPORT_FILE"; then
        log "SUCCESS: Found correct destination for tunnel 2"
    else
        log "FAIL: Missing correct destination for tunnel 2: $EXPECTED_DEST2"
        RESULT=3
    fi
else
    log "FAIL: Report file not created."
    RESULT=4
fi

exit "$RESULT"
