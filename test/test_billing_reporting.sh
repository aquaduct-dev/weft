#!/usr/bin/env bash
# test/test_billing_reporting.sh
# Purpose: Verify that the weft server sends usage reports containing
# tunnel name, source, and destination fields when a tunnel shuts down.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

log "Logs will be written to $LOGDIR"

# --- Test Steps ---

# 1) Start Mock Usage Reporting Server
start_mock_report_server

# 2) Start Target HTTP Server
start_target_http_server "hello-usage-tracking"

# 3) Start Weft Server with usage reporting enabled
start_weft_server_with_reporting

# 4) Start Weft Tunnel
REMOTE_PORT=$(find_free_port)
TUNNEL_NAME="billing-test-tunnel"
LOCAL_URL="http://127.0.0.1:${TARGET_PORT}"
REMOTE_URL="http://127.0.0.1:${REMOTE_PORT}"

start_weft_tunnel "$TUNNEL_NAME" "$LOCAL_URL" "$REMOTE_URL"

# 5) Generate Traffic
log "Generating traffic..."
curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null
curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null
curl -s "http://127.0.0.1:$REMOTE_PORT" > /dev/null

# 6) Gracefully Shutdown Tunnel
stop_tunnel_gracefully "$TUNNEL_PID"

# 7) Verify Usage Report
log "Checking usage report..."
if [ -f "$REPORT_FILE" ]; then
    cat "$REPORT_FILE"
    
    # Check tunnel name
    if grep -q "$TUNNEL_NAME" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained tunnel name '$TUNNEL_NAME'"
    else
        log "FAIL: Usage report did not contain tunnel name '$TUNNEL_NAME'"
        exit 3
    fi

    # Check source field
    if grep -qF "\"source\":\"$LOCAL_URL\"" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained correct source '$LOCAL_URL'"
    else
        log "FAIL: Usage report did NOT contain correct source '$LOCAL_URL'"
        exit 3
    fi

    # Check destination field
    if grep -qF "\"destination\":\"$REMOTE_URL\"" "$REPORT_FILE"; then
        log "SUCCESS: Usage report contained correct destination '$REMOTE_URL'"
    else
        log "FAIL: Usage report did NOT contain correct destination '$REMOTE_URL'"
        exit 3
    fi
    
    RESULT=0
else
    log "FAIL: Report file not created."
    exit 4
fi

exit "$RESULT"
