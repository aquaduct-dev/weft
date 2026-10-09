<!-- docdaemon ts:2026-10-09T01:40:59Z hash:079eb0a066c5f5a7 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script performs an end-to-end integration test for the Weft TCP proxy by verifying that HTTP traffic is correctly forwarded from a client through the proxy to a backend Python server.

### Purpose
The file validates the core functionality of the `weft` CLI proxy command. It ensures that the compiled binary can successfully establish a listening socket, forward connections to a target service, and return expected responses.

### Workflow
1. **Setup**: Locates free ports for both the backend server and the proxy listener using `find_free_port`. Creates a dummy `index.html` in the log directory to serve as static content.
2. **Backend Initialization**: Starts `python3 -m http.server` on the allocated backend port. The script blocks until the port is open (`wait_for_port`).
3. **Proxy Launch**: Invokes `$WEFT_BIN proxy` with verbose logging, pointing it at the backend URL and binding to the proxy listener port.
4. **Verification**: Retries `curl` requests up to 10 times with a 0.5s delay to check if the response contains "hello-from-http-server".
5. **Teardown & Reporting**: On failure, dumps both proxy and Python logs to stdout for debugging. Exits with code `0` on success or `3` on failure.

### Dependencies
- Sourced library functions: `lib.sh` (provides `log`, `cleanup`, `find_free_port`, `wait_for_port`).
- Environment variables: `WEFT_BIN` (path to the compiled binary), `PROTO` (defaults to `tcp`), `LOGDIR` (output directory).