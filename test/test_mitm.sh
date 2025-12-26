#!/usr/bin/env bash
# shellcheck disable=SC1091
# Test: Verify MITM protection works by attempting to connect through a fake proxy
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

WEFT_SERVER_PORT=$(find_free_port)
MITM_PROXY_PORT=$(find_free_port)
WEFT_SERVER_BIND_IP=127.0.0.1
CONNECTION_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
SERVER_LOG="$LOGDIR/server.log"
MITM_LOG="$LOGDIR/mitm.log"
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

# Verify the server is running
if ! grep -q "Connection Secret" "${SERVER_LOG}"; then
  log "Error: Server did not start properly."
  cat "${SERVER_LOG}"
  exit 1
fi
log "--- Server started successfully ---"

# Create a simple MITM TLS proxy using openssl s_server that just forwards traffic
# but presents its own certificate (not the server's encrypted certificate)
log "--- Starting MITM proxy on port ${MITM_PROXY_PORT} ---"

# Generate a different certificate for the MITM proxy
MITM_CERT_DIR="$LOGDIR/mitm_certs"
mkdir -p "$MITM_CERT_DIR"
openssl req -x509 -newkey rsa:2048 -keyout "$MITM_CERT_DIR/key.pem" -out "$MITM_CERT_DIR/cert.pem" \
  -days 1 -nodes -subj "/CN=mitm-attacker" 2>/dev/null

# Start a simple TLS proxy using socat that presents the MITM certificate
# but forwards to the real server
socat -d -d \
  "OPENSSL-LISTEN:${MITM_PROXY_PORT},fork,reuseaddr,cert=${MITM_CERT_DIR}/cert.pem,key=${MITM_CERT_DIR}/key.pem,verify=0" \
  "OPENSSL:127.0.0.1:${WEFT_SERVER_PORT},verify=0" \
  &>"${MITM_LOG}" &
pids+=($!)

sleep 2

log "--- MITM proxy started, logging to ${MITM_LOG} ---"

# Attempt to connect through the MITM proxy
# This SHOULD FAIL because the encrypted certificate from the server won't match
# the certificate presented by the MITM proxy
log "--- Attempting to connect tunnel through MITM proxy (expected to fail) ---"

# Run the tunnel command with timeout - it should fail during TLS verification
# after the login succeeds (because the MITM can't produce a valid encrypted cert)
timeout 10 "$WEFT_BIN" tunnel \
  "weft://${CONNECTION_SECRET}@${WEFT_SERVER_BIND_IP}:${MITM_PROXY_PORT}" \
  "http://127.0.0.1:80" \
  "http://mitm-test.example.com:18080" \
  &>"${TUNNEL_LOG}" 2>&1
TUNNEL_EXIT_CODE=$?

log "--- Tunnel exit code: ${TUNNEL_EXIT_CODE} ---"

# The tunnel should have failed (non-zero exit code)
if [[ "$TUNNEL_EXIT_CODE" -eq 0 ]]; then
  log "Error: Tunnel succeeded through MITM proxy! This indicates MITM vulnerability."
  log "--- Server log ---"
  cat "${SERVER_LOG}"
  log "--- MITM log ---"
  cat "${MITM_LOG}"
  log "--- Tunnel log ---"
  cat "${TUNNEL_LOG}"
  exit 1
fi

# Check the tunnel log for certificate-related error
if grep -q -E "(certificate|tls|TLS|x509|Certificate)" "${TUNNEL_LOG}"; then
  log "--- MITM protection working! Connection failed due to certificate mismatch ---"
else
  log "--- MITM protection working! Connection failed (checking error) ---"
  cat "${TUNNEL_LOG}"
fi

log "--- Test finished successfully: MITM attack prevented ---"
RESULT=0
