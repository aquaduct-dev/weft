<!-- docdaemon ts:2026-10-09T01:41:03Z hash:28770923558a7d39 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script performs an end-to-end integration test for the Weft UDP proxy by orchestrating a Python server, the proxy binary, and a client connection to verify data flow.

### Purpose
The file validates that the `weft` CLI correctly proxies UDP traffic from a listening port to a target backend. It ensures the proxy handles packet forwarding and response delivery without errors.

### Key Components
- **Test Environment Setup**: Uses `lib.sh` for shared utilities like `find_free_port`, `log`, and `cleanup`.
- **Mock Backend**: Spawns a temporary Python UDP server (`udp_server.py`) that echoes a specific string (`hello-from-python-udp-server`).
- **Proxy Orchestration**: Starts the compiled `WEFT_BIN` in proxy mode, binding to a free local port and targeting the Python server.
- **Verification Loop**: Repeatedly sends a "hello" message via `nc` (netcat) to the proxy port until the expected response is received or retries are exhausted.

### Execution Flow
1.  **Initialize**: Source library functions and set up exit traps for cleanup.
2.  **Start Backend**: Launch the Python server on a dynamic port and wait for it to bind.
3.  **Start Proxy**: Launch the Weft proxy pointing to the backend and wait for it to bind.
4.  **Test Connectivity**: Send UDP packets through the proxy. If the response matches the expected string, the test passes (exit code 0). Otherwise, it logs proxy and server outputs and fails (exit code 3).