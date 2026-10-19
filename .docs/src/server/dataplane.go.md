<!-- docdaemon ts:2026-10-19T23:25:56Z hash:a46a23d7a115a3b3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the core tunneling dataplane, managing WireGuard peer state and HTTP/TCP/UDP proxy lifecycle.

### `TunnelDataplane`
The main struct holding the WireGuard device, private key, and a `ProxyManager`. It coordinates between network tunnels and application-level proxies.

### Key Functions

*   **`NewTunnelDataplane`**: Initializes the WireGuard device and proxy manager. Sets up cleanup hooks for graceful shutdown.
*   **`UpdateWireGuardConfig`**: Incrementally reconciles WireGuard peers. Instead of replacing all peers (which discards learned roaming endpoints), it adds new peers and removes departed ones to maintain connectivity stability during churn.
*   **`StartProxy`**: Creates a proxy instance for a specific tunnel request. It determines the protocol (TCP, UDP, HTTP, HTTPS) and configures source/destination URLs. For HTTPS, it optionally injects custom TLS certificates if provided in the request.
*   **`CloseProxy`**: Terminates a named proxy instance.
*   **`GetProxyCounters`**: Returns traffic statistics (Tx/Rx bytes) for all active proxies.
*   **ACME/Certificate Management**: Methods like `SetACMEEmail`, `ListCertificates`, and `RegisterACMERedirect` delegate to the underlying VHost proxy manager to handle TLS certificate issuance, caching, and ACME challenge redirection.