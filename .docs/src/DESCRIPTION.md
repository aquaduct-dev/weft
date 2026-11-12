<!-- docdaemon ts:2026-11-12T09:41:02Z hash:27129e9ad309c02d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src` directory implements the core Weft server infrastructure, managing secure tunnel lifecycle, authentication, and network proxying.

## Overview
This package orchestrates the connection between public endpoints and internal services via WireGuard tunnels. It handles the full request lifecycle from JWT-based challenge-response authentication to dynamic IP allocation and reverse proxy management. The system ensures reliability through adaptive health monitoring, automatic certificate issuance, and robust error handling for distributed environments.

## Deep Dive
### Authentication and Security
The server enforces strict access controls using a multi-step challenge-response flow. Clients exchange encrypted challenges for signed JWTs, validated against a shared connection secret. Middleware ensures all protected routes require valid tokens, while constant-time comparisons prevent timing attacks. Optional TLS pinning mitigates man-in-the-middle risks during initial handshakes.

### Tunnel Lifecycle Management
Tunnel establishment involves validating JWT claims, allocating IPs from a subnet pool, and configuring the WireGuard dataplane. Removal triggers cleanup of proxies, IP releases, and peer deletion. WireGuard configuration updates are incremental to preserve learned roaming endpoints, preventing disruption during churn. A background janitor sweeps stale tunnels to prevent resource leaks.

### Resilience and Observability
Operational health is monitored through Prometheus-compatible metrics and JSON status reports. An adaptive health monitor adjusts retry intervals based on server responses, treating permanent failures as fatal events. The ACME helper manages certificate issuance with rate-limit protection and peer-to-peer challenge proxying to handle round-robin DNS scenarios, ensuring availability even when nodes share hostnames.

## Key Interfaces
- `Server`: Main struct holding HTTP listener, store, dataplane, and secrets.
- `Dataplane`: Interface for WireGuard configuration and proxy lifecycle management.
- `TunnelStore`: Abstraction for peer state and IP address allocation.
- `Janitor`: Background worker for removing stale tunnels.
- `NewACMEHelper`: Constructs an ACME helper wrapping an autocert manager.
- `GetToken`: Executes the challenge-response login and returns a JWT.
- `WithJWT`: An `http.RoundTripper` wrapper for automatic Bearer token injection.
- `ProxyManager`: Central coordinator for creating, starting, and stopping proxy instances.
- `HealthMonitor`: Adaptive health checking logic for verifying server connectivity.

## Dependencies
- Internal packages: `auth`, `client`, `crypto`, `proxy`, `server`, `tunnel`, `types`, `wireguard`.
- External libraries: `ginkgo`, `gomega`, `wgctrl`, `prometheus`, `jwt-go`, `autocert`.

## Subcomponents
- `acme/`: Certificate issuance and HTTP-01 challenge validation.
- `auth/`: Zero-trust authentication and JWT lifecycle management.
- `client/`: Go client library for tunnel management and health monitoring.
- `crypto/`: Cryptographic utilities for login exchanges and certificate generation.
- `dns/`: Cloudflare DNS record synchronization.
- `internal/`: Immutable network configuration constants and low-level utilities.
- `logging/`: Centralized application-wide logging configuration.
- `proxy/`: Multi-protocol tunnel manager forwarding traffic through WireGuard.
- `server/`: Control plane managing tunnel lifecycle and observability.
- `tunnel/`: Client-side WireGuard tunnel setup and proxy configuration.
- `version/`: Application build metadata exposed at runtime.