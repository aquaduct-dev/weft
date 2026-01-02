#!/usr/bin/env bash
set -uo pipefail

# Find weft binary
if [[ -n "${RUNFILES_DIR:-}" && -f "${RUNFILES_DIR}/_main/weft" ]]; then
    WEFT_BIN="${RUNFILES_DIR}/_main/weft"
elif [[ -f "./weft" ]]; then
    WEFT_BIN="./weft"
else
    WEFT_BIN=$(find . -name weft -type f | head -n 1)
fi

if [[ -z "$WEFT_BIN" || ! -f "$WEFT_BIN" ]]; then
    # Fallback for bazel raw binary
    WEFT_BIN=$(find . -name weft_raw -type f | head -n 1)
fi

LOGDIR=$(mktemp -d /tmp/weft-test-XXXX)
RESULT=1
pids=()

log() {
    echo "[$(basename "$0")] $*" >&2
}

cleanup() {
    log "Cleaning up..."
    for pid in "${pids[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    
    if [[ "$RESULT" -ne 0 ]]; then
        log "Test failed. Logs retained at $LOGDIR"
        # Optional: print logs if in CI or if requested
        if [[ "${VERBOSE:-0}" -ne 0 ]]; then
            grep "" "$LOGDIR"/*.log || true
        fi
    else
        rm -rf "$LOGDIR"
        log "Test passed."
    fi
}

find_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'
}

wait_for_port() {
    local port=$1
    local host=${2:-127.0.0.1}
    local timeout=${3:-10}
    log "Waiting for $host:$port to be open..."
    for i in $(seq 1 "$timeout"); do
        if nc -z "$host" "$port" >/dev/null 2>&1; then
            log "$host:$port is open."
            return 0
        fi
        sleep 0.5
    done
    log "Timed out waiting for $host:$port."
    return 1
}

wait_for_udp_port() {
    # For UDP there's no connect check; we just sleep briefly to allow bind.
    sleep 0.5
}

# --- Billing Test Helpers ---

# Creates the mock usage reporting server Python script
# Usage: create_mock_report_server_script
create_mock_report_server_script() {
    cat <<'EOF' > "$LOGDIR/mock_report_server.py"
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
}

# Starts mock usage reporting server
# Sets: REPORT_PORT, REPORT_FILE, REPORT_URL
# Usage: start_mock_report_server
start_mock_report_server() {
    REPORT_PORT=$(find_free_port)
    REPORT_FILE="$LOGDIR/usage.json"
    REPORT_URL="http://127.0.0.1:$REPORT_PORT/report"
    
    create_mock_report_server_script
    
    log "Starting mock reporting server on port $REPORT_PORT..."
    python3 "$LOGDIR/mock_report_server.py" "$REPORT_PORT" "$REPORT_FILE" >"$LOGDIR/report_server.log" 2>&1 &
    pids+=($!)
    wait_for_port "$REPORT_PORT"
}

# Starts weft server with usage reporting enabled
# Requires: REPORT_URL to be set
# Sets: SERVER_PORT, CONN_SECRET
# Usage: start_weft_server_with_reporting
start_weft_server_with_reporting() {
    SERVER_PORT=$(find_free_port)
    local secret_file="$LOGDIR/secret"
    
    log "Starting weft server on port $SERVER_PORT with usage reporting..."
    "$WEFT_BIN" server --verbose --port "$SERVER_PORT" --secret-file "$secret_file" --usage-reporting-url "$REPORT_URL" >"$LOGDIR/server.log" 2>&1 &
    pids+=($!)
    
    # Wait for secret file
    for i in $(seq 1 10); do
        if [ -f "$secret_file" ]; then
            break
        fi
        sleep 0.5
    done
    
    if [ ! -f "$secret_file" ]; then
        log "Failed to find secret file."
        cat "$LOGDIR/server.log"
        exit 2
    fi
    
    CONN_SECRET=$(cat "$secret_file" | tr -d '\n')
    log "Found connection secret."
}

# Starts a simple HTTP target server
# Args: $1 - content to serve (optional, defaults to "hello")
# Sets: TARGET_PORT
# Usage: start_target_http_server [content]
start_target_http_server() {
    local content="${1:-hello}"
    TARGET_PORT=$(find_free_port)
    
    echo "$content" > "$LOGDIR/index.html"
    
    log "Starting target http.server on port $TARGET_PORT..."
    python3 -m http.server "$TARGET_PORT" --directory "$LOGDIR" >"$LOGDIR/target.log" 2>&1 &
    pids+=($!)
    wait_for_port "$TARGET_PORT"
}

# Starts a weft tunnel
# Requires: CONN_SECRET, SERVER_PORT to be set
# Args: $1 - tunnel name, $2 - local URL, $3 - remote URL
# Sets: TUNNEL_PID
# Usage: start_weft_tunnel "tunnel-name" "http://127.0.0.1:LOCAL" "http://127.0.0.1:REMOTE"
start_weft_tunnel() {
    local tunnel_name="$1"
    local local_url="$2"
    local remote_url="$3"
    local weft_url="weft://${CONN_SECRET}@127.0.0.1:${SERVER_PORT}"
    
    log "Starting weft tunnel '$tunnel_name'..."
    "$WEFT_BIN" tunnel --verbose --tunnel-name "$tunnel_name" "$weft_url" "$local_url" "$remote_url" >"$LOGDIR/${tunnel_name}.log" 2>&1 &
    TUNNEL_PID=$!
    pids+=($TUNNEL_PID)
    
    # Extract remote port from URL and wait for it
    local remote_port
    remote_port=$(echo "$remote_url" | sed 's/.*:\([0-9]*\)$/\1/')
    wait_for_port "$remote_port"
}

# Stops a tunnel gracefully and waits for shutdown
# Args: $1 - tunnel PID
# Usage: stop_tunnel_gracefully $TUNNEL_PID
stop_tunnel_gracefully() {
    local tunnel_pid="$1"
    log "Stopping tunnel (sending SIGTERM to $tunnel_pid)..."
    kill -TERM "$tunnel_pid"
    wait "$tunnel_pid" || true
    # Wait for server to process shutdown and send report
    sleep 2
}
