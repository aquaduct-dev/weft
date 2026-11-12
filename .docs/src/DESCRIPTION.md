<!-- docdaemon ts:2026-11-12T09:11:41Z hash:8f1f4dd6a18eb9a2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src` directory implements the core Weft server infrastructure, managing secure tunnel lifecycle, authentication, and network proxying.

## Overview
This package orchestrates the connection between public endpoints and internal services using WireGuard tunnels. It handles zero-trust authentication via challenge-response JWTs, manages TLS certificate issuance through ACME, and provides multi-protocol proxying for HTTP, TCP, and UDP traffic. The codebase is structured to separate cryptographic primitives, network configuration, and application logic into distinct subpackages for maintainability.

## Deep Dive
### Authentication and Security
The `auth` package enforces zero-trust principles by validating client secrets through encrypted challenge-response exchanges. It manages JWT lifecycles with automatic renewal and supports optional TLS fingerprint pinning to prevent man-in-the-middle attacks during initial handshakes. The `crypto` package provides low-level AES-GCM encryption and self-signed certificate generation for these secure channels.

### Tunnel Management and Proxying
The `server` package acts as the control plane, allocating IPs from a subnet pool and coordinating WireGuard dataplane updates. The `proxy` package forwards traffic through gVisor-based WireGuard interfaces, supporting HTTP/3 and virtual host routing. It includes resilience features like sliding-window failure tracking to prevent premature tunnel teardowns during transient upstream outages.

### Certificate and DNS Automation
Automated HTTPS setup is handled by the `acme` package, which wraps `autocert.Manager` to manage certificate lifecycles. It implements a fan-out proxy to distribute HTTP-01 challenges across sibling bastions in round-robin DNS environments, ensuring validation succeeds regardless of which node the CA contacts. The `dns` package synchronizes Cloudflare records with strict zone resolution to prevent cross-zone pollution.

### Client-Side Connectivity
The `client` package provides programmatic access to administrative endpoints and includes an adaptive health monitor. This monitor uses exponential backoff for transient errors and treats permanent failures (like 404s after eviction) as fatal events, triggering process termination to avoid silent degradation. The `tunnel` package on the client side orchestrates WireGuard device creation and local proxy startup.

## Key Interfaces
- `GetToken`: Executes challenge-response login and returns a signed JWT.
- `NewClient`: Initializes an administrative client with JWT-based auth.
- `ProxyManager`: Coordinates active TCP, UDP, and HTTP tunnel instances.
- `Server`: Main struct holding HTTP listener, store, and dataplane.
- `Tunnel`: Orchestrates full client-side connection lifecycle.
- `HealthMonitor`: Adaptive loop verifying server connectivity with backoff.
- `ACMEHelper`: Manages certificate acquisition and HTTP-01 challenge proxying.
- `UpdateRecord`: Synchronizes Cloudflare DNS records for a hostname.

## Dependencies
- `github.com/cloudflare/cloudflare-go`: DNS record management.
- `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
- `golang.org/x/crypto/acme/autocert`: Let's Encrypt integration.
- `github.com/rs/zerolog`: Structured logging.
- `github.com/golang-jwt/jwt/v4`: JWT handling.
- `go.uber.org/zap`: Alternative logging backend.
- Standard library: `net`, `crypto/tls`, `sync`.

## Subcomponents
- `acme/`: TLS certificate acquisition and challenge validation.
- `auth/`: Zero-trust authentication and JWT management.
- `client/`: Administrative client and health monitoring.
- `crypto/`: Symmetric encryption and certificate generation.
- `dns/`: Cloudflare DNS synchronization.
- `internal/`: Network constants and URL utilities.
- `logging/`: Centralized zerolog configuration.
- `proxy/`: Multi-protocol tunnel manager and vhost routing.
- `server/`: Control plane, handlers, and janitor workers.
- `tunnel/`: Client-side WireGuard device orchestration.
- `version/`: Build metadata injection.