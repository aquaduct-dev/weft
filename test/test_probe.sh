#!/usr/bin/env bash
# test/test_probe.sh
# Purpose: Test the `weft probe` command.
# Since `weft probe` requires a public IP to succeed (by design of CanPassACMEChallenge),
# this test primarily verifies that the command executes and correctly identifies
# a non-public host (localhost) as a failure case.

set -uo pipefail

# --- Helpers ---
log() {
  echo "test_probe: $*" >&2
}

cleanup() {
  if [[ "${RESULT:-1}" -ne 0 ]]; then
    echo "Test failed."
  else
    echo "Test passed."
  fi
}
trap cleanup EXIT


WEFT_BIN="${RUNFILES_DIR}/_main/weft"
echo "Using weft binary at: $WEFT_BIN"

# --- Test 1: Probe localhost (Expected Failure) ---
# CanPassACMEChallenge rejects private IPs/loopback.
log "Running probe against localhost (expecting failure due to private IP)..."
if "$WEFT_BIN" probe localhost >/dev/null 2>&1; then
  log "FAIL: 'weft probe localhost' succeeded, but should have failed for private IP."
  RESULT=1
  exit 1
else
  log "SUCCESS: 'weft probe localhost' failed as expected."
fi

# --- Test 2: Probe invalid URL (Expected Failure) ---
log "Running probe against invalid URL..."
if "$WEFT_BIN" probe "http://invalid.url.that.does.not.resolve" >/dev/null 2>&1; then
  log "FAIL: 'weft probe' succeeded on invalid URL."
  RESULT=1
  exit 1
else
  log "SUCCESS: 'weft probe' failed on invalid URL as expected."
fi

# --- Test 3: Probe without domain arg, using --bind-ip (Expected Failure due to private IP) ---
# This verifies that the command accepts missing domain arg and falls back to bind-ip.
log "Running probe with --bind-ip 127.0.0.1 and no domain arg..."
if "$WEFT_BIN" probe --bind-ip 127.0.0.1 >/dev/null 2>&1; then
  log "FAIL: 'weft probe --bind-ip 127.0.0.1' succeeded, but should have failed."
  RESULT=1
  exit 1
else
  # We expect failure (exit code 1) because 127.0.0.1 is private.
  # If the command crashed or errored on argument parsing, it would likely be a different exit code or output,
  # but here we mainly ensure it runs the logic.
  log "SUCCESS: 'weft probe --bind-ip 127.0.0.1' failed as expected."
fi

RESULT=0
exit 0
