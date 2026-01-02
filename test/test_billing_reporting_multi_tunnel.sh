#!/usr/bin/env bash
# test/test_billing_reporting_multi_tunnel.sh
# Purpose: Verify that the weft server correctly reports usage for multiple
# tunnels from the same client when they shut down.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Mock Usage Reporting Server
start_mock_report_server

# 2) Start Two Target HTTP Servers
mkdir -p "$LOGDIR/target1" "$LOGDIR/target2"
echo "hello-from-target1" > "$LOGDIR/target1/index.html"
echo "hello-from-target2" > "$LOGDIR/target2/index.html"

TARGET_PORT1=$(find_free_port)
log "Starting target http.server 1 on port $TARGET_PORT1..."
python3 -m http.server "$TARGET_PORT1" --directory "$LOGDIR/target1" >"$LOGDIR/target1.log" 2>&1 &
pids+=($!)
wait_for_port "$TARGET_PORT1"

TARGET_PORT2=$(find_free_port)
log "Starting target http.server 2 on port $TARGET_PORT2..."
python3 -m http.server "$TARGET_PORT2" --directory "$LOGDIR/target2" >"$LOGDIR/target2.log" 2>&1 &
pids+=($!)
wait_for_port "$TARGET_PORT2"

# 3) Start Weft Server with usage reporting enabled
start_weft_server_with_reporting

# 4) Start First Weft Tunnel
REMOTE_PORT1=$(find_free_port)
TUNNEL_NAME1="billing-test-tunnel-1"
LOCAL_URL1="http://127.0.0.1:${TARGET_PORT1}"
REMOTE_URL1="http://127.0.0.1:${REMOTE_PORT1}"

start_weft_tunnel "$TUNNEL_NAME1" "$LOCAL_URL1" "$REMOTE_URL1"
TUNNEL_PID1=$TUNNEL_PID

# 5) Start Second Weft Tunnel
REMOTE_PORT2=$(find_free_port)
TUNNEL_NAME2="billing-test-tunnel-2"
LOCAL_URL2="http://127.0.0.1:${TARGET_PORT2}"
REMOTE_URL2="http://127.0.0.1:${REMOTE_PORT2}"

start_weft_tunnel "$TUNNEL_NAME2" "$LOCAL_URL2" "$REMOTE_URL2"
TUNNEL_PID2=$TUNNEL_PID

# 6) Generate Traffic on Both Tunnels
log "Generating traffic on tunnel 1..."
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT1" > /dev/null || true
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT1" > /dev/null || true

log "Generating traffic on tunnel 2..."
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT2" > /dev/null || true
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT2" > /dev/null || true
curl -s --max-time 5 "http://127.0.0.1:$REMOTE_PORT2" > /dev/null || true

# 7) Gracefully Shutdown Both Tunnels
stop_tunnel_gracefully "$TUNNEL_PID1"
stop_tunnel_gracefully "$TUNNEL_PID2"

# 8) Verify Usage Reports
log "Checking usage reports..."
RESULT=0

if [ -f "$REPORT_FILE" ]; then
    cat "$REPORT_FILE"
    
    # Check for both tunnels
    for name in "$TUNNEL_NAME1" "$TUNNEL_NAME2"; do
        if grep -q "$name" "$REPORT_FILE"; then
            log "SUCCESS: Usage report contained tunnel name '$name'"
        else
            log "FAIL: Usage report did not contain tunnel name '$name'"
            RESULT=3
        fi
    done

    # Verify we got at least two reports
    REPORT_COUNT=$(wc -l < "$REPORT_FILE")
    if [ "$REPORT_COUNT" -ge 2 ]; then
        log "SUCCESS: Received $REPORT_COUNT usage reports (expected at least 2)"
    else
        log "FAIL: Only received $REPORT_COUNT usage report(s), expected at least 2"
        RESULT=3
    fi

    # Verify source/destination for both tunnels
    for i in 1 2; do
        eval "src=\$LOCAL_URL$i"
        eval "dst=\$REMOTE_URL$i"
        
        if grep -qF "\"source\":\"$src\"" "$REPORT_FILE"; then
            log "SUCCESS: Found correct source for tunnel $i"
        else
            log "FAIL: Missing correct source for tunnel $i: $src"
            RESULT=3
        fi
        if grep -qF "\"destination\":\"$dst\"" "$REPORT_FILE"; then
            log "SUCCESS: Found correct destination for tunnel $i"
        else
            log "FAIL: Missing correct destination for tunnel $i: $dst"
            RESULT=3
        fi
    done
else
    log "FAIL: Report file not created."
    RESULT=4
fi

exit "$RESULT"
