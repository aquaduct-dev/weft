<!-- docdaemon ts:2026-10-09T01:40:55Z hash:207611434c37d3a5 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script validates the `weft probe` command by verifying it correctly rejects private IPs and invalid URLs.

The file serves as an integration test for the `weft probe` subcommand, ensuring network validation logic functions as intended. It sources `lib.sh` for logging and cleanup utilities, then executes three specific scenarios against the binary defined in `$WEFT_BIN`.

### Test Scenarios

1.  **Localhost Rejection**: Probes `localhost` to confirm that `CanPassACMEChallenge` correctly blocks private/loopback addresses.
2.  **Invalid URL Handling**: Probes a non-resolvable domain (`http://invalid.url.that.does.not.resolve`) to ensure the command fails gracefully on DNS resolution errors.
3.  **Bind-IP Fallback**: Runs `probe --bind-ip 127.0.0.1` without a domain argument to verify that the fallback mechanism respects private IP restrictions.

Each test expects a non-zero exit code. If any test succeeds (exit code 0) when failure is expected, the script logs a failure and exits immediately with status 1. Successful completion of all tests results in an exit code of 0.