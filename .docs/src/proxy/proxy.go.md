<!-- docdaemon ts:2026-10-19T23:25:52Z hash:36e520cd270aa64a model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the `ProxyManager` and concrete proxy implementations (`TCP`, `UDP`, `VHost`) that handle tunnel lifecycle, connection forwarding, and protocol translation.

### Core Components

**ProxyManager**
Orchestrates active proxies via a name-to-`Proxy` map. It enforces uniqueness (returning `ErrProxyAlreadyExists` or `ErrProxyConflict`) and delegates HTTP/HTTPS routing to `VHostProxyManager`. The `StartProxy` method inspects source/destination schemes to instantiate the correct proxy type.

**TCPProxy**
Forwards TCP streams between public and target endpoints. It uses `WGAwareTCPDial` for upstream connections. To prevent premature teardown during brief outages, it employs a sliding-window failure tracker (`util.FailureTracker`); cleanup is triggered only after sustained dial failures within a configured window.

**UDPProxy**
Manages UDP sessions using a source-address-keyed map protected by a mutex to prevent concurrent map write panics. A dedicated response goroutine is spawned once per new source address to handle upstream reads and write responses back to the client.

**VHostRouteProxy**
Handles HTTP/HTTPS traffic by registering routes with the VHost manager. It supports ACME-based automatic TLS certificate issuance when no PEM data is provided, or explicit TLS configuration otherwise. Matchers and modifiers are parsed from URL fragments to control request routing.

### Key Types & Errors

*   **`ProxyManager`**: Central coordinator for all proxy instances.
*   **`ErrProxyAlreadyExists`**, **`ErrProxyConflict`**: Sentinel errors used by callers to classify startup failures (e.g., mapping to HTTP 409).
*   **`TCPDialFailureThreshold`**, **`TCPDialFailureWindow`**: Configuration constants controlling the resilience of TCP tunnels against transient upstream failures.