#!/usr/bin/env bash
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

WEFT_SERVER_PORT=$(find_free_port)
WEFT_SERVER_BIND_IP=127.0.0.1
CONNECTION_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
SERVER_LOG="$LOGDIR/server.log"
TUNNEL_LOG="$LOGDIR/tunnel.log"

log "--- Starting weft server with connection secret ---"
"$WEFT_BIN" server \
  --port="${WEFT_SERVER_PORT}" \
  --bind-ip="${WEFT_SERVER_BIND_IP}" \
  --connection-secret="${CONNECTION_SECRET}" \
  &>"${SERVER_LOG}" &
pids+=($!)

log "--- Server started, logging to ${SERVER_LOG} ---"

# Give the server some time to start up
sleep 3

# Verify the connection secret is in the logs
log "--- Verifying connection secret in server logs ---"
if ! grep -q "Connection Secret" "${SERVER_LOG}"; then
  log "Error: 'Connection Secret' not found in server logs."
  cat "${SERVER_LOG}"
  kill "${SERVER_PID}"
  exit 1
fi

if ! grep -q "${CONNECTION_SECRET}" "${SERVER_LOG}"; then
  log "Error: Connection secret '${CONNECTION_SECRET}' not found in server logs."
  cat "${SERVER_LOG}"
  kill "${SERVER_PID}"
  exit 1
fi
log "--- Connection secret found in server logs ---"


log "--- Attempting to connect without correct secret (expected to fail) ---"
if "$WEFT_BIN" tunnel "weft://wrong-secret@${WEFT_SERVER_BIND_IP}:${WEFT_SERVER_PORT}" "http://127.0.0.1:80" "http://weft.example.com:18080"; then
  log "Error: Connection succeeded without the correct secret, but was expected to fail."
  kill "${SERVER_PID}"
  exit 1
fi
log "--- Connection without correct secret failed as expected ---"


log "--- Attempting to connect with correct secret (expected to succeed) ---"
# We just check if it starts (and then we kill it) or returns a specific error if tunnel setup fails immediately.
# Since 'tunnel' command runs indefinitely on success, we can run it with a timeout or in background.
# For this test, let's run it in background and check logs or PID.
TUNNEL_LOG="/tmp/weft_tunnel_secret_test.log"
"$WEFT_BIN" tunnel "weft://${CONNECTION_SECRET}@${WEFT_SERVER_BIND_IP}:${WEFT_SERVER_PORT}" "http://127.0.0.1:80" "http://weft.example.com:18080" &> "${TUNNEL_LOG}" &
TUNNEL_PID=$!

sleep 2

if ! kill -0 "$TUNNEL_PID"; then
    log "Error: Tunnel process died unexpectedly."
    cat "${TUNNEL_LOG}"
    kill "${SERVER_PID}"
    exit 1
fi

log "--- Connection with correct secret succeeded as expected ---"
log "--- Test finished successfully ---"
