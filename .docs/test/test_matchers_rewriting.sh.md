<!-- docdaemon ts:2026-10-09T01:41:04Z hash:b804b7dea77cf2a8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script tests the Weft tunnel's query parameter matching logic by verifying that requests are only proxied to the upstream when a specific token is present.

### Purpose
The file orchestrates an integration test for the `weft` binary, ensuring that the tunnel correctly filters traffic based on URL query parameters. It validates that valid tokens reach the backend while invalid ones are rejected.

### Key Components
- **Upstream Server**: A temporary Python HTTP server (`upstream.py`) simulates a backend application. It returns `200 OK` for `/api/v1/create` and `404` otherwise.
- **Weft Server**: The central Weft server instance is started with a generated secret file to authenticate connections.
- **Weft Tunnel**: A tunnel is established linking the local upstream to a remote virtual host (`my-app.example.com`). The `REMOTE_URL` includes `?token=secret`, configuring the tunnel to match this query string.
- **Validation Logic**: Two `curl` requests are sent:
  - A valid request with `?token=secret` expects a `200` response body of `ok`.
  - An invalid request with `?token=wrong` expects a `404` status code, indicating the tunnel did not forward the request because the matcher failed.

### Integration
This test relies on `lib.sh` for utilities like `find_free_port`, `wait_for_port`, and logging. It cleans up all spawned processes (Python server, Weft server, and tunnel) upon exit via a trap.