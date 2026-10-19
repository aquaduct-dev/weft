<!-- docdaemon ts:2026-10-15T20:43:08Z hash:174e491e4197db0f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src` directory contains the core Go packages implementing the Weft proxy service, including server orchestration, client libraries, and networking infrastructure.

## Overview
This package aggregates the primary business logic for tunnel management, authentication, and traffic forwarding. It serves as the central hub for the application, coordinating between the control plane (server) and data plane (proxies/WireGuard). The structure is organized into distinct functional domains to ensure modularity and testability across the complex interaction of cryptographic handshakes, DNS updates, and network routing.

## Deep Dive
### Server Orchestration
The `server` package acts as the central coordinator, managing WireGuard lifecycle, peer state, and HTTP API endpoints. It integrates with `proxy` for traffic forwarding and `acme` for automated TLS certificate issuance. Background janitors clean up stale tunnels, while usage reporters send metrics to external systems.

### Client and Tunnel Management
The `client` library provides programmatic access to the administrative API, handling JWT authentication and adaptive health monitoring. The `tunnel` package implements the client-side WireGuard connection logic, abstracting device configuration and proxy integration to establish secure channels to the server.

### Security and Cryptography
Authentication relies on a zero-trust challenge-response flow in the `auth` package, using AES-GCM encryption and JWTs. The `crypto` package offers symmetric encryption utilities and self-signed certificate generation for local testing. TLS fingerprint pinning ensures identity verification during the handshake process.

### Networking and Proxying
The `proxy` package manages TCP, UDP, and HTTP/HTTPS virtual host proxies, integrating with WireGuard for transparent layer-4 forwarding. It handles conflict detection, concurrency safety, and automatic TLS via ACME. The `dns` module abstracts Cloudflare interactions to maintain accurate DNS records for tunnel endpoints.

## Key Interfaces
*   `Server`: Central coordinator embedding `http.Server`, managing routes, state, and background workers.
*   `Client`: Library struct for programmatically managing tunnels and monitoring health.
*   `ProxyManager`: Controller for creating, starting, and closing proxy tunnels.
*   `Tunnel`: Main function to establish the client-side WireGuard connection.
*   `ACMEHelper`: Wrapper for `autocert.Manager` handling certificate acquisition and caching.
*   `UpdateRecord`: Function to update Cloudflare DNS records for a hostname.
*   `Init`: Configures the global zerolog logger instance.

## Dependencies
*   `github.com/aquaduct-dev/weft/src/acme`
*   `github.com/aquaduct-dev/weft/src/auth`
*   `github.com/aquaduct-dev/weft/src/client`
*   `github.com/aquaduct-dev/weft/src/crypto`
*   `github.com/aquaduct-dev/weft/src/dns`
*   `github.com/aquaduct-dev/weft/src/internal/constants`
*   `github.com/aquaduct-dev/weft/src/internal/util`
*   `github.com/aquaduct-dev/weft/src/logging`
*   `github.com/aquaduct-dev/weft/src/proxy`
*   `github.com/aquaduct-dev/weft/src/server`
*   `github.com/aquaduct-dev/weft/src/tunnel`
*   `github.com/aquaduct-dev/weft/src/types`
*   `github.com/aquaduct-dev/weft/src/version`
*   `github.com/aquaduct-dev/weft/src/wireguard`
*   External: `golang.org/x/crypto/acme/autocert`, `github.com/rs/zerolog`, `github.com/onsi/ginkgo/v2`, `github.com/onsi/gomega`, `github.com/cloudflare/cloudflare-go`

## Subcomponents
*   `acme/`
*   `auth/`
*   `client/`
*   `crypto/`
*   `dns/`
*   `internal/`
*   `logging/`
*   `proxy/`
*   `server/`
*   `tunnel/`
*   `version/`
*   `BUILD.bazel`

Co-located integration tests (package `server_test`, not production code):
*   `server_connectivity_test.go`
*   `server_eviction_repro_test.go`
*   `server_tunnel_suite_test.go`
*   `server_tunnel_test.go`

The `wireguard/` and `types/` packages live at the repository root, not under `src/`.