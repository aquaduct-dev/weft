<!-- docdaemon ts:2026-10-09T01:40:59Z hash:6ac2fae68ebb5c2e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script performs an end-to-end integration test for the Weft CLI, verifying that TCP tunnels correctly forward HTTP traffic from a local Python server to a remote endpoint.

### Purpose
The file orchestrates a multi-process environment to validate the `weft` binary's tunneling capabilities. It ensures that a client can connect to a remote port and receive data served by a backend process through the Weft infrastructure.

### Workflow
1.  **Setup**: Sources `lib.sh` for utilities like `find_free_port`, `wait_for_port`, and logging. Sets up a trap to clean up child processes on exit.
2.  **Backend Service**: Starts a Python `http.server` on a dynamic port, serving a static `index.html`.
3.  **Weft Server**: Launches the `weft` server binary. It waits for the server to generate a secret file, which is then read to authenticate subsequent connections.
4.  **Tunnel Creation**: Initiates a `weft tunnel` command, binding the local Python server to a new remote port using the retrieved connection secret.
5.  **Verification**: Polls the remote port using `curl` until the expected response string ("hello-from-http-server") is received.

### Key Components
-   **Process Management**: Child PIDs are tracked in the `pids` array for cleanup.
-   **Secret Handling**: The server generates a secret file upon startup; the script reads this value to construct the `WEFT_URL`.
-   **Retry Logic**: Both the server startup wait and the final HTTP verification loop use retries with short sleeps to handle race conditions.
-   **Logging**: All subprocess output is redirected to log files in `$LOGDIR` for debugging if the test fails.