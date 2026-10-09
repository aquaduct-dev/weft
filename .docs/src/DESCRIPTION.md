<!-- docdaemon ts:2026-10-09T01:48:10Z hash:16315fc725a03103 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src` directory contains the core implementation of the Weft proxy service, including server orchestration, client libraries, and infrastructure packages for networking, security, and automation.

## Overview
This package serves as the central codebase for the Weft project, bridging HTTP API endpoints with underlying WireGuard networking infrastructure. It manages the full lifecycle of tunnel connections, from authentication and certificate issuance to traffic forwarding and health monitoring. By organizing functionality into distinct subpackages like `server`, `client`, and `proxy`, it ensures modularity and testability across complex distributed systems.

## Deep Dive
### Server Orchestration
The `server` package acts as the control plane, coordinating tunnel creation, peer state management, and background janitor tasks. It integrates with ACME for automated TLS certificates and uses a challenge-response flow for secure JWT-based authentication. The dataplane abstraction handles WireGuard device synchronization and proxy coordination, ensuring consistent state during concurrent updates.

### Client and Tunnel Management
The `client` package provides a Go library for programmatic tunnel interaction, featuring adaptive health monitoring with exponential backoff. The `tunnel` package implements the client-side WireGuard connection logic, abstracting userspace device configuration and proxy integration. Together, they ensure stable connectivity and automatic recovery from transient network failures.

### Security and Cryptography
Security is enforced through the `auth` package’s zero-trust challenge-response flow and AES-GCM encryption. The `crypto` package offers symmetric encryption utilities and self-signed certificate generation for local testing. TLS fingerprint pinning in `auth` validates server identity, while `acme` handles peer-to-peer redirect coordination for distributed certificate validation.

### Infrastructure and Utilities
Supporting packages handle DNS updates via Cloudflare (`dns`), structured logging (`logging`), and build metadata (`version`). The `internal` package centralizes network constants and failure tracking utilities, preventing configuration drift. The `proxy` package orchestrates TCP, UDP, and HTTP/HTTPS virtual host routing, integrating with WireGuard netstack for transparent layer-4 forwarding.

## Key Interfaces
*   `Server`: Central coordinator embedding `http.Server`, managing routes, state, and background workers.
*   `Client`: Library struct for programmatically managing tunnels and monitoring health status.
*   `ProxyManager`: Central controller for creating, starting, and closing proxy tunnels.
*   `ACMEHelper`: Struct wrapping `autocert.Manager` for certificate acquisition and caching.
*   `Tunnel`: Main function to establish the client-side WireGuard connection and start the proxy.
*   `UpdateRecord(token, hostname, targetIP)`: Updates DNS records for a hostname to point to a target IP.
*   `Init(level zerolog.Level)`: Configures the global logger with specified level and environment-aware formatting.
*   `Encrypt(key, text string) ([]byte, error)`: Performs AES-256-GCM encryption using a SHA-256 derived key.
*   `GetToken`: Executes the challenge-response login sequence and returns a JWT and server certificate.
*   `Login`: Orchestrates full setup, verifies certificates, and returns an authenticated `http.Client`.

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
*   External: `golang.org/x/crypto/acme/autocert`, `github.com/rs/zerolog`, `github.com/onsi/ginkgo/v2`, `github.com/onsi/gomega`, `github.com/google/gopacket`, `go.uber.org/zap`, `github.com/quic-go/quic-go`, `github.com/cloudflare/cloudflare-go`

## Subcomponents
*   `BUILD.bazel`
*   `server_connectivity_test.go`
*   `server_eviction_repro_test.go`
*   `server_tunnel_suite_test.go`
*   `server_tunnel_test.go`
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