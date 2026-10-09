<!-- docdaemon ts:2026-10-09T01:40:36Z hash:87075c9e562259cb model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `TunnelDataplane` struct, which manages WireGuard device state and proxies traffic for individual peer tunnels.

### Purpose
The `TunnelDataplane` acts as the central coordinator for a single WireGuard interface. It handles the lifecycle of the underlying userspace device, maintains peer configurations incrementally to preserve learned endpoints, and delegates proxy management (TCP/UDP/HTTP) to an embedded `ProxyManager`.

### Key Types and Functions

#### `TunnelDataplane` Struct
Holds the WireGuard device instance, private key, listen port, and proxy manager. It ensures thread-safe updates via a mutex.

#### `NewTunnelDataplane`
Initializes the dataplane by creating a new WireGuard device on the specified port and binding IP. It sets up the proxy manager with cleanup handlers.

#### `UpdateWireGuardConfig`
Synchronizes the device's peers with the desired set. It performs incremental add/remove operations rather than a full rebuild to prevent wiping learned roaming endpoints for active peers.

#### `StartProxy`
Creates a network proxy for a specific peer request. It determines the protocol (TCP, UDP, HTTP, HTTPS), generates a random local port, and configures source/destination URLs based on the request modifiers. For HTTPS, it optionally injects custom certificates.

#### `CloseProxy`
Terminates a named proxy instance managed by the proxy manager.

#### `GetProxyCounters`
Returns byte transmission and reception statistics for all active proxies.

#### ACME/TLS Management
- `SetACMEEmail`: Configures the email for Let's Encrypt certificate issuance.
- `SetCertsCachePath`: Sets the directory for caching TLS certificates.
- `ListCertificates`: Returns metadata for cached certificates.
- `RegisterACMERedirect`: Registers a peer IP for ACME challenge redirection for a specific host.