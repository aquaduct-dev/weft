<!-- docdaemon ts:2026-10-30T02:44:48Z hash:6ae1c3b49558f3ca model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src` directory implements the core Weft server infrastructure, managing secure tunnel lifecycle, authentication, and multi-protocol proxying.

## Overview
This package serves as the central control plane for Weft, orchestrating client connections via WireGuard tunnels and exposing administrative HTTP endpoints. It enforces zero-trust security through challenge-response JWT authentication and manages dynamic IP allocation within a private subnet. The system ensures reliable connectivity by integrating adaptive health monitoring, automatic TLS certificate issuance, and robust error handling for distributed environments.

## Deep Dive
### Authentication and Security
The server validates clients using encrypted challenge-response exchanges to issue signed JWTs. Middleware protects all routes except public version checks, ensuring only authorized peers can establish tunnels or trigger shutdowns. Optional TLS pinning mitigates man-in-the-middle risks during initial handshakes, while AES-GCM encryption secures sensitive payloads like certificates and secrets.

### Tunnel Lifecycle Management
Tunnel establishment involves validating JWT claims, allocating IPs from a pool, and configuring the WireGuard dataplane. A background janitor periodically sweeps the store, evicting peers that fail health checks for three consecutive intervals (~15–20 seconds). This eviction triggers client-side crash loops if the backend is unreachable, preventing resource leaks from stale connections.

### Proxy Orchestration and Resilience
The proxy manager coordinates TCP, UDP, and virtual host (HTTP/HTTPS) forwarding. Virtual hosts handle complex routing with longest-prefix matching and ACME-based TLS issuance. To support clustered deployments with round-robin DNS, HTTP-01 challenges are proxied to sibling nodes rather than redirected, avoiding Let's Encrypt restrictions on bare-IP redirects. Failure trackers prevent premature tunnel teardowns during transient upstream outages.

## Key Interfaces
- `Server`: Main struct holding HTTP listener, store, dataplane, and secrets.
- `Dataplane`: Interface for WireGuard configuration and proxy lifecycle management.
- `ProxyManager`: Orchestrates active proxies and resolves conflicts.
- `VHostProxyManager`: Coordinates virtual hosts, ACME issuance, and challenge relays.
- `HealthMonitor`: Adaptive loop verifying server connectivity with exponential backoff.
- `GetToken`: Executes challenge-response login and returns a JWT and encrypted certificate.

## Dependencies
- Internal packages: `auth`, `crypto`, `proxy`, `server`, `tunnel`, `types`, `wireguard`.
- External libraries: `golang.org/x/crypto/acme/autocert`, `github.com/rs/zerolog`, `github.com/cloudflare/cloudflare-go`, `prometheus`.

## Subcomponents
- `acme/`: Certificate acquisition and HTTP-01 challenge proxying.
- `auth/`: Zero-trust authentication, JWT management, and crypto helpers.
- `client/`: Administrative client library and health monitoring.
- `crypto/`: Symmetric encryption and self-signed certificate generation.
- `dns/`: Cloudflare DNS record synchronization.
- `internal/`: Network constants, URL utilities, and failure tracking.
- `logging/`: Centralized zerolog configuration.
- `proxy/`: Multi-protocol tunnel manager and virtual host routing.
- `server/`: Control plane logic, handlers, and janitor workers.
- `tunnel/`: Client-side WireGuard device setup and proxy integration.
- `version/`: Build metadata injection and reporting.