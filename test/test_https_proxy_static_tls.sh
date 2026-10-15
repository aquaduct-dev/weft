#!/usr/bin/env bash
# test/test_https_proxy_static_tls.sh
# Purpose: end-to-end test for `weft proxy` serving several https hostnames
# from one process with a static, CA-signed certificate (--tls-cert/--tls-key)
# instead of ACME. This is the mode weft-operator's WeftLocalDNSReflector uses
# to terminate TLS for public hostnames inside a cluster. The client verifies
# the chain against the test CA (no -k), and each hostname must reach its own
# backend.

# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
trap cleanup EXIT

TMPDIR="$(mktemp -d)"
log "Logs will be written to $LOGDIR"

if ! command -v openssl >/dev/null 2>&1; then
  log "openssl is required for this test"
  exit 3
fi

# --- 1) CA + leaf with SANs for both hostnames ---
CA_KEY="$TMPDIR/ca.key"
CA_CERT="$TMPDIR/ca.crt"
KEY="$TMPDIR/tls.key"
CSR="$TMPDIR/tls.csr"
CERT="$TMPDIR/tls.crt"
EXT="$TMPDIR/ext.cnf"

log "Generating test CA and leaf certificate for a.weft.test,b.weft.test"
openssl req -x509 -nodes -days 1 -newkey rsa:2048 -subj "/CN=weft-test-ca" \
  -keyout "$CA_KEY" -out "$CA_CERT" >/dev/null 2>&1
openssl req -nodes -newkey rsa:2048 -subj "/CN=a.weft.test" \
  -keyout "$KEY" -out "$CSR" >/dev/null 2>&1
printf 'subjectAltName=DNS:a.weft.test,DNS:b.weft.test\n' >"$EXT"
openssl x509 -req -days 1 -in "$CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAcreateserial -extfile "$EXT" -out "$CERT" >/dev/null 2>&1
if [[ ! -s "$CERT" ]]; then
  log "Certificate generation failed"
  exit 4
fi

# --- 2) Two plain HTTP backends that identify themselves ---
cat >"$LOGDIR/serve_http.py" <<'PYCODE'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(sys.argv[2].encode())
HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
PYCODE

A_PORT=$(find_free_port)
B_PORT=$(find_free_port)
log "Starting backend A on $A_PORT and backend B on $B_PORT"
python3 "$LOGDIR/serve_http.py" "$A_PORT" "hello-from-a" >"$LOGDIR/a.log" 2>&1 &
pids+=($!)
python3 "$LOGDIR/serve_http.py" "$B_PORT" "hello-from-b" >"$LOGDIR/b.log" 2>&1 &
pids+=($!)
wait_for_port "$A_PORT" || exit 5
wait_for_port "$B_PORT" || exit 5

# --- 3) One weft proxy process, two pairs, static TLS ---
PROXY_PORT=$(find_free_port)
PROXY_LOG="$LOGDIR/proxy.log"
log "Starting weft proxy with static TLS on $PROXY_PORT"
"$WEFT_BIN" proxy --verbose --tls-cert "$CERT" --tls-key "$KEY" \
  "http://127.0.0.1:${A_PORT}" "https://a.weft.test:${PROXY_PORT}" \
  "http://127.0.0.1:${B_PORT}" "https://b.weft.test:${PROXY_PORT}" \
  >"$PROXY_LOG" 2>&1 &
pids+=($!)
wait_for_port "$PROXY_PORT" || { cat "$PROXY_LOG"; exit 6; }

# --- 4) Verify each hostname against the CA, routed to its own backend ---
fetch() {
  local host=$1
  curl -s --cacert "$CA_CERT" --resolve "${host}:${PROXY_PORT}:127.0.0.1" \
    "https://${host}:${PROXY_PORT}/"
}

set +e
A_OUT="" B_OUT=""
for i in $(seq 1 10); do
  A_OUT=$(fetch a.weft.test)
  B_OUT=$(fetch b.weft.test)
  if [[ "$A_OUT" == "hello-from-a" && "$B_OUT" == "hello-from-b" ]]; then
    break
  fi
  sleep 0.5
done
set -e

log "a.weft.test -> '$A_OUT'"
log "b.weft.test -> '$B_OUT'"

if [[ "$A_OUT" == "hello-from-a" && "$B_OUT" == "hello-from-b" ]]; then
  log "SUCCESS: both hostnames verified against the CA and reached their own backend"
  RESULT=0
else
  log "FAIL: unexpected responses"
  echo "proxy log -----"
  cat "$PROXY_LOG"
  RESULT=3
fi
exit "$RESULT"
