<!-- docdaemon ts:2026-10-09T01:40:24Z hash:fe0da7f5f273870c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `ProxyManager` which orchestrates the lifecycle, creation, and routing of TCP, UDP, and HTTP/HTTPS virtual host proxies.

### Overview
The `ProxyManager` maintains a registry of active proxies keyed by name, ensuring no duplicate names or conflicting configurations exist. It delegates specific protocol handling to `TCPProxy`, `UDPProxy`, and `VHostRouteProxy` instances, while managing shared VHost listeners via `vhost.VHostProxyManager`.

### Key Types & Functions

*   **`ProxyManager`**: The central controller. Use `NewProxyManager()` to initialize. Call `SetBindIP()` to constrain listeners.
*   **`StartProxy`**: The primary entry point for creating new tunnels. It parses source/destination URLs, validates constraints (ports, conflicts), and instantiates the appropriate proxy type (`tcp>tcp`, `udp>udp`, `http>http`, etc.). For HTTPS routes, it supports either explicit TLS certificates or automatic ACME issuance.
*   **`Close`**: Terminates a named proxy and removes it from the registry.
*   **`GetProxyCounters`**: Returns a snapshot of traffic statistics (Tx/Rx bytes) for all active proxies.

### Implementation Details
*   **TCP Proxying**: Uses `WGAwareTCPListen/Dial` to integrate with WireGuard's netstack. Includes failure tracking (`TCPDialFailureThreshold`) to automatically clean up tunnels after sustained upstream dial failures.
*   **UDP Proxying**: Maintains per-source-address sessions in a mutex-protected map to prevent concurrent map writes. Spawns response goroutines only when a new source address is detected.
*   **HTTP/HTTPS Routing**: Parses URL fragments for matchers (query params, headers) and modifiers (redirects). Routes requests through the VHost manager, supporting path prefix rewriting and header manipulation.