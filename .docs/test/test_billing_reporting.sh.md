<!-- docdaemon ts:2026-10-09T01:40:59Z hash:1db211eedcbb40bd model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the weft server correctly includes tunnel name, source, and destination fields in usage reports upon graceful shutdown.

## Purpose
The test ensures end-to-end billing reporting accuracy by simulating a tunnel lifecycle: startup, traffic generation, and graceful termination. It validates that the final report file contains the expected metadata.

## Key Functions
- `start_mock_report_server`: Listens for incoming usage reports.
- `start_target_http_server`: Provides the backend service for the tunnel.
- `start_weft_server_with_reporting`: Launches the weft daemon with reporting enabled.
- `start_weft_tunnel`: Establishes the tunnel between local and remote endpoints.
- `stop_tunnel_gracefully`: Triggers the shutdown sequence that generates the report.

## Workflow
1. **Setup**: Initializes mock servers and the weft environment.
2. **Execution**: Generates HTTP traffic through the tunnel to ensure data flow.
3. **Teardown**: Gracefully stops the tunnel, prompting the server to write the report.
4. **Verification**: Checks the report file for specific JSON fields (`tunnel_name`, `source`, `destination`). Exits with error codes if validation fails or the file is missing.