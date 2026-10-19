<!-- docdaemon ts:2026-10-19T23:26:03Z hash:536cc3aef33770b8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script validates that the Weft server enforces connection secrets by verifying log output and testing tunnel authentication success and failure paths.

### Purpose
The test ensures that the `--connection-secret` flag correctly restricts access to the Weft server. It generates a random secret, starts the server with it, and then verifies two scenarios:
1.  **Logging:** The server logs the presence of the connection secret.
2.  **Authentication:** A tunnel using an incorrect secret fails immediately with a "login failed" error, while a tunnel using the correct secret establishes successfully.

### Key Behaviors
*   **Setup:** Generates a 32-character alphanumeric secret and finds a free port. Starts the server in the background, logging to `$LOGDIR/server.log`.
*   **Log Verification:** Checks `server.log` for the string "Connection Secret" and the specific generated secret value. This check was added to ensure visibility into secret handling during startup.
*   **Negative Test (Wrong Secret):** Runs the tunnel command with a hardcoded wrong secret. It expects a non-zero exit code (specifically checking against timeout hang `124`) and a "login failed" message in the logs. Previous versions failed due to unbound variable errors in cleanup traps; this version uses `timeout` to prevent hangs and tracks PIDs for proper cleanup.
*   **Positive Test (Correct Secret):** Runs the tunnel command with the valid secret. It verifies the process remains alive after a short sleep, indicating successful authentication. The PID is tracked in the `pids` array for cleanup on exit.