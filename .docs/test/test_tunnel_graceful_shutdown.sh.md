<!-- docdaemon ts:2026-10-09T01:41:00Z hash:63b940f6b3690b27 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script performs an end-to-end test of the Weft CLI to verify that tunnels survive process restarts and maintain connectivity.

It orchestrates a Python HTTP server, the Weft server, and a tunnel instance to validate graceful shutdown and reconnection logic. The test ensures that after killing and restarting the tunnel process, the remote endpoint remains accessible and returns the expected response.

### Key Functions
- **`find_free_port`**: Allocates ephemeral ports for the Python server, Weft server, and tunnel remote endpoints to avoid conflicts.
- **`wait_for_port`**: Blocks until a specific port is listening, ensuring dependencies are ready before proceeding.
- **Secret Management**: Waits for the Weft server to generate a secret file, reads it, and uses it to construct the connection URL for the tunnel.
- **HTTP Verification**: Uses `curl` in a loop to confirm the tunneled service serves the dummy `index.html`.

### Test Flow
1.  **Setup**: Starts a local Python HTTP server and the Weft server.
2.  **Tunnel Creation**: Establishes a tunnel from the local Python server to a remote port via the Weft server.
3.  **Validation**: Confirms initial connectivity by fetching content over the tunnel.
4.  **Restart Simulation**: Kills the tunnel process, waits briefly, then restarts it with the same configuration.
5.  **Post-Restart Validation**: Verifies that the restarted tunnel successfully serves requests again.

### Integration
This script relies on `lib.sh` for logging and cleanup utilities. It requires `$WEFT_BIN` to be set to the compiled Weft binary. Cleanup is handled automatically via a trap on EXIT to terminate all background processes.