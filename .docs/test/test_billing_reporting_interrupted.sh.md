<!-- docdaemon ts:2026-10-09T01:40:59Z hash:1578bc143184b334 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that billing usage reports accurately account for data transferred during interrupted or canceled HTTP connections.

### Purpose
The test ensures the Weft server correctly reports byte counts (`bytes_tx`/`bytes_rx`) even when a client disconnects mid-transfer. It simulates this scenario by connecting to a slow-response mock server and terminating the request early.

### Key Components
- **Mock Slow Server**: A Python HTTP server (`slow_server.py`) that sends chunked responses with delays, allowing the test to interrupt the connection before completion.
- **Weft Integration**: Starts the Weft server with reporting enabled and creates a tunnel between the local slow server and a remote port.
- **Interruption Logic**: Uses `timeout 0.5 curl` to force an early termination of the HTTP request, simulating a user closing the browser or network drop.
- **Verification**: Checks the generated `$REPORT_FILE` for the presence of the tunnel name and non-zero byte counts to confirm partial data was captured.

### Context
This file is part of the integration test suite (`test/`). It relies on helper functions from `lib.sh` (e.g., `start_weft_server_with_reporting`, `find_free_port`) and cleans up processes via the `cleanup` trap on exit.