<!-- docdaemon ts:2026-10-30T02:43:14Z hash:514e8f1047ae5b03 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `TunnelDataplane`, which manages WireGuard tunnels and their associated reverse proxies.

The `TunnelDataplane` struct encapsulates a WireGuard userspace device, its private key, and a `ProxyManager` for handling traffic routing. It is initialized via `NewTunnelDataplane`, which creates the WireGuard interface and configures the proxy manager with bind addresses and cleanup handlers.

Key responsibilities include:

*   **Peer Management (`UpdateWireGuardConfig`)**: Incrementally reconciles WireGuard peers by adding new ones or removing departed ones without wiping learned endpoints. This prevents connection drops during churn, as full replacement would discard roaming state (see commit `f873faf145`).
*   **Proxy Lifecycle (`StartProxy`, `CloseProxy`)**: Spawns reverse proxies for tunnel traffic. It dynamically selects ports and protocols (TCP/UDP/HTTP/HTTPS), handling TLS certificate injection for HTTPS tunnels.
*   **ACME Integration**: Delegates ACME challenge listening and certificate caching to the underlying `VHostProxyManager`. The challenge listener remains active to support sibling bastions in round-robin DNS setups (see commit `ca9e4eee22`).
*   **Observability**: Exposes proxy counters, cached certificates, and ACME failure states for monitoring endpoints.