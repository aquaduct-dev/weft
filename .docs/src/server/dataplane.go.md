<!-- docdaemon ts:2026-10-29T21:04:48Z hash:a80835c6154e93e2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `TunnelDataplane`, managing WireGuard device state and proxying traffic for client tunnels.

The `TunnelDataplane` struct encapsulates a WireGuard userspace device, its private key, and an associated `ProxyManager`. It initializes by creating the WireGuard device on a specified port and binding IP, then configuring the proxy manager with cleanup handlers.

Key responsibilities include:

*   **Peer Reconciliation (`UpdateWireGuardConfig`)**: Incrementally adds or removes peers to preserve learned endpoints (roaming state). This avoids the "churn storm" where replacing all peers wipes return paths for active tunnels. It parses the current IPC config to identify existing keys and only applies diffs.
*   **Proxy Management**: Spawns proxies for incoming tunnel requests via `StartProxy`, supporting TCP, UDP, HTTP, and HTTPS protocols. For HTTPS, it optionally injects custom TLS certificates. Proxies are identified by name and can be closed individually.
*   **Certificate & ACME Integration**: Delegates certificate listing and ACME failure reporting to the underlying `VHostProxyManager`, exposing them for monitoring endpoints.

The dataplane is designed for high-churn environments where maintaining persistent connections across dynamic peer sets is critical.