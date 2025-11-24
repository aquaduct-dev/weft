#!/bin/bash

set -euo pipefail

if [[ -z "${RUNFILES_DIR:-}" ]]; then
  RUNFILES_DIR="$0.runfiles"
fi
WEFT_BIN="${RUNFILES_DIR}/_main/weft"
if [[ ! -x "$WEFT_BIN" ]]; then
    WEFT_BIN="weft"
fi

WEFT_SERVER_PORT=28080
WEFT_SERVER_BIND_IP=127.0.0.1
CONNECTION_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
SERVER_LOG="/tmp/weft_server_secret_test.log"
TUNNEL_LOG="/tmp/weft_tunnel_secret_test.log"
SERVER_PID=""
TUNNEL_PID=""

cleanup() {
  echo "--- Cleaning up ---"
  if [[ -n "$TUNNEL_PID" ]]; then
    kill "$TUNNEL_PID" 2>/dev/null || true
    wait "$TUNNEL_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "${SERVER_LOG}" "${TUNNEL_LOG}"
}
trap cleanup EXIT

echo "--- Starting weft server with connection secret ---"
"$WEFT_BIN" server \
  --port="${WEFT_SERVER_PORT}" \
  --bind-ip="${WEFT_SERVER_BIND_IP}" \
  --connection-secret="${CONNECTION_SECRET}" \
  &>"${SERVER_LOG}" &
SERVER_PID=$!

echo "--- Server started with PID ${SERVER_PID}, logging to ${SERVER_LOG} ---"

# Give the server some time to start up
sleep 3

# Verify the connection secret is in the logs
echo "--- Verifying connection secret in server logs ---"
if ! grep -q "Connection Secret" "${SERVER_LOG}"; then
  echo "Error: 'Connection Secret' not found in server logs."
  cat "${SERVER_LOG}"
  kill "${SERVER_PID}"
  exit 1
fi

if ! grep -q "${CONNECTION_SECRET}" "${SERVER_LOG}"; then
  echo "Error: Connection secret '${CONNECTION_SECRET}' not found in server logs."
  cat "${SERVER_LOG}"
  kill "${SERVER_PID}"
  exit 1
fi
echo "--- Connection secret found in server logs ---"


echo "--- Attempting to connect without correct secret (expected to fail) ---"
if "$WEFT_BIN" tunnel "weft://wrong-secret@${WEFT_SERVER_BIND_IP}:${WEFT_SERVER_PORT}" "http://127.0.0.1:80" "http://weft.example.com:18080"; then
  echo "Error: Connection succeeded without the correct secret, but was expected to fail."
  kill "${SERVER_PID}"
  exit 1
fi
echo "--- Connection without correct secret failed as expected ---"


echo "--- Attempting to connect with correct secret (expected to succeed) ---"
# We just check if it starts (and then we kill it) or returns a specific error if tunnel setup fails immediately.
# Since 'tunnel' command runs indefinitely on success, we can run it with a timeout or in background.
# For this test, let's run it in background and check logs or PID.
TUNNEL_LOG="/tmp/weft_tunnel_secret_test.log"
"$WEFT_BIN" tunnel "weft://${CONNECTION_SECRET}@${WEFT_SERVER_BIND_IP}:${WEFT_SERVER_PORT}" "http://127.0.0.1:80" "http://weft.example.com:18080" &> "${TUNNEL_LOG}" &
TUNNEL_PID=$!

sleep 2

if ! kill -0 "$TUNNEL_PID"; then
    echo "Error: Tunnel process died unexpectedly."
    cat "${TUNNEL_LOG}"
    kill "${SERVER_PID}"
    exit 1
fi

echo "--- Connection with correct secret succeeded as expected ---"
echo "--- Test finished successfully ---"
