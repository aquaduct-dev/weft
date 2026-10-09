<!-- docdaemon ts:2026-10-09T01:42:15Z hash:a68cdb886faee4fa model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `server` directory implements the Weft control plane, managing WireGuard tunnel lifecycle, authentication, and network dataplane orchestration.

## Overview
This package serves as the central coordinator for the Weft proxy service, bridging HTTP API endpoints with underlying networking infrastructure. It handles client authentication via challenge-response JWTs, manages peer state in an in-memory store, and orchestrates WireGuard device configuration through a dedicated dataplane abstraction. Background workers ensure system hygiene by cleaning up stale tunnels and reporting usage metrics to external systems.

## Deep Dive
### Authentication and Security
The server enforces strict access controls using a multi-step challenge-response flow. Clients request a challenge, respond with a signed token, and receive a JWT for subsequent authenticated requests. Metrics endpoints use Basic Auth with constant-time comparison to prevent timing attacks. TLS certificates are managed via ACME redirects, allowing peers to validate Let's Encrypt challenges through DNS-based authorization.

### Tunnel Lifecycle Management
Tunnel creation involves validating JWT claims, allocating IP addresses from a subnet pool, and updating the WireGuard configuration incrementally to preserve learned roaming endpoints. The `ConnectHandler` orchestrates this process, while `RemoveTunnel` ensures atomic cleanup of proxies, IPs, and peer metadata. A background janitor periodically sweeps for inactive tunnels based on health check timestamps, preventing resource leaks.

### Data Plane and Proxying
The `TunnelDataplane` struct manages the WireGuard interface and embedded proxy manager. It supports TCP, UDP, and HTTP/HTTPS traffic forwarding, injecting custom certificates where needed. Traffic statistics are aggregated from proxy counters and exposed via Prometheus-compatible metrics and JSON APIs. Thread-safe operations ensure consistent state during concurrent tunnel updates.

## Key Interfaces
- `Server`: Central coordinator embedding `http.Server`, managing routes, state, and background workers.
- `TunnelStore`: Interface for thread-safe peer CRUD operations, IP allocation, and last-seen tracking.
- `Dataplane`: Interface for WireGuard device synchronization, proxy management, and ACME redirection.
- `Janitor`: Background worker that identifies and removes stale tunnels based on health check intervals.
- `HTTPUsageReporter`: Component that aggregates and POSTs tunnel traffic statistics to an external endpoint.

## Dependencies
- `github.com/aquaduct-dev/weft/src/acme`: ACME protocol handling for certificate issuance.
- `github.com/aquaduct-dev/weft/src/crypto`: Cryptographic utilities for encryption and key generation.
- `github.com/aquaduct-dev/weft/src/dns`: DNS resolution and record management.
- `github.com/aquaduct-dev/weft/src/proxy`: Network proxy implementation for traffic forwarding.
- `github.com/aquaduct-dev/weft/src/version`: Build metadata and version information.
- External libraries: JWT handling, logging (zerolog), and WireGuard management.

## Subcomponents
- `BUILD.bazel`: Bazel build rules for the server package and tests.
- `dataplane.go`: WireGuard device state management and proxy coordination.
- `handlers_acme_redirect.go`: HTTP handler for ACME challenge redirection.
- `handlers_auth.go`: Challenge-response authentication and JWT issuance.
- `handlers_certificates.go`: Handler for listing cached TLS certificates.
- `handlers_health.go`: Health check report processing.
- `handlers_metrics.go`: Prometheus and JSON metrics exposure.
- `handlers_tunnel.go`: Tunnel connection, management, and shutdown logic.
- `handlers_version.go`: Build metadata endpoint.
- `janitor.go`: Stale tunnel cleanup worker.
- `middleware.go`: JWT validation middleware and context helpers.
- `server.go`: Main server initialization and route registration.
- `store.go`: In-memory peer and IP address storage.
- `test_data/`: Directory containing test PEM certificates and keys.
- `test_helpers_test.go`: Test stubs for dataplane interactions.
- `types.go`: Core data structures and interface definitions.
- `usage_reporter.go`: Periodic usage statistics reporting.