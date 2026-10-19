<!-- docdaemon ts:2026-10-19T23:25:58Z hash:b09354be36b0fbd3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains Ginkgo integration tests that validate the server’s ability to tunnel HTTP, HTTPS, and TCP traffic through a WireGuard interface.

It spins up an in-process `server.Server` alongside a dummy backend, authenticates using generated WireGuard keys, and verifies end-to-end connectivity. Key behaviors tested include:

*   **Protocol Tunneling**: Validates `http>http`, `http>https`, and `tcp>tcp` forwarding via the `tunnel.Tunnel` function.
*   **Security Enforcement**: Confirms that the `/connect` endpoint binds the tunnel name to the JWT subject (F-3), preventing cross-tunnel authorization.
*   **Feature Verification**: Checks usage reporting to a mock endpoint and DNS updates when Cloudflare tokens are configured.
*   **Robustness**: Uses `Eventually` assertions to handle race conditions during server startup and connection establishment.