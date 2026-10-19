<!-- docdaemon ts:2026-10-19T23:25:57Z hash:c41265832fe1d6d7 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file tests the server’s automatic tunnel eviction when a backend becomes unreachable.

It sets up an isolated environment with a mock HTTP backend and a test server instance to verify connectivity health checks. The `BeforeEach` block initializes a free port for the backend, generates a WireGuard keypair, and authenticates to obtain a valid JWT token.

The primary test case, "removes tunnel when backend is unreachable", validates the janitor’s cleanup logic:
1. It establishes a tunnel by sending a connect request and starting the client-side device.
2. It confirms the tunnel appears in the server’s list via `ListHandler`.
3. It stops the backend listener to simulate failure.
4. It waits for the tunnel to disappear from the list, accounting for the janitor’s 5-second sweep interval and the three-interval eviction threshold (~15-20s).