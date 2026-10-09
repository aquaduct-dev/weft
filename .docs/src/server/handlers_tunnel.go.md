<!-- docdaemon ts:2026-10-09T01:40:43Z hash:f8a2be2dc306128b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the HTTP handlers and core logic for establishing, managing, and tearing down WireGuard tunnels via a proxy service.

### Purpose
The `Server` type exposes endpoints to handle client lifecycle events. It validates JWT claims against tunnel names to prevent unauthorized access (F-3), allocates IP addresses, configures the WireGuard dataplane, and manages DNS updates for proxied traffic.

### Key Functions

*   **`ConnectHandler`**: The entry point for new connections. It enforces that the `tunnel_name` in the request matches the JWT subject (`sub`). If no name is provided, it defaults to the subject. It delegates to `Serve` and returns configuration details or error codes.
*   **`Serve`**: Orchestrates the connection setup. It parses the client public key, calls `getOrCreateTunnelPeer` to allocate resources, updates the WireGuard configuration on the dataplane, and starts the HTTP/HTTPS proxy. On failure, it performs cleanup by removing the newly created tunnel.
*   **`getOrCreateTunnelPeer`**: Interacts with the `Store` to retrieve an existing peer or create a new one with an allocated IP. If a new peer is created and Cloudflare integration is enabled, it asynchronously updates the DNS record for the specified hostname.
*   **`ShutdownHandler`**: Handles disconnection requests. It reports usage metrics and triggers `RemoveTunnel`.
*   **`RemoveTunnel`**: Cleans up all resources associated with a tunnel name. This includes closing the proxy, releasing the IP address from the store, deleting peer metadata, and syncing the WireGuard configuration to remove the stale peer.

### Integration
This file sits between the HTTP layer and the internal `proxy`, `Store`, and `Dataplane` abstractions. It ensures data consistency by rolling back changes if intermediate steps (like starting the proxy) fail after the peer has been created.