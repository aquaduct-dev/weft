<!-- docdaemon ts:2026-10-19T23:27:20Z hash:d3dd22692596eccb model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src/server` package implements the Weft control plane, managing WireGuard tunnel lifecycle, authentication, and ACME certificate issuance.

## Overview
This directory serves as the central coordination point for the Weft bastion host, bridging HTTP API endpoints with underlying networking primitives. It handles peer registration, IP allocation, and proxy configuration while enforcing strict security policies via JWT-based authentication and constant-time secret comparisons. The server also includes background janitors to clean up stale tunnels and reporters to aggregate usage metrics.

## Deep Dive
### Tunnel Lifecycle & Dataplane
The `TunnelDataplane` struct orchestrates WireGuard device state and HTTP/TCP/UDP proxies. Peer configuration is reconciled incrementally to preserve learned roaming endpoints, preventing connectivity loss during churn. The `Store` manages peer metadata and IP address allocation within a defined subnet, ensuring atomic creation to avoid leaks.

### Authentication & Security
Authentication uses a challenge-response flow issuing signed JWTs. The `/login` endpoint generates encrypted challenges, while other routes require valid tokens via `requireJWT` middleware. Metrics endpoints use Basic Auth with constant-time comparison to prevent timing attacks. TLS certificates are managed via ACME, with peer-to-peer redirects for HTTP-01 challenges.

### Maintenance & Observability
A `Janitor` goroutine periodically sweeps for stale tunnels that have missed health checks, removing them to free resources. Usage data is aggregated by an `HTTPUsageReporter` and sent to external endpoints. Prometheus-compatible metrics and JSON statistics are exposed for monitoring, with careful escaping of label values to prevent injection.

## Key Interfaces
*   `Server`: Main coordinator embedding `http.Server`, handling mux, store, and dataplane.
*   `TunnelDataplane`: Manages WireGuard peers, proxy instances, and ACME certificate state.
*   `InMemoryTunnelStore`: Thread-safe storage for peer records, IPs, and last-seen timestamps.
*   `Janitor`: Background worker that identifies and removes inactive tunnels based on health reports.
*   `HTTPUsageReporter`: Periodic sender of tunnel traffic statistics to a configured URL.

## Dependencies
*   `//src/acme`: Certificate management and ACME protocol handling.
*   `//src/crypto`: Cryptographic utilities for encryption and hashing.
*   `//src/dns`: DNS resolution and record updates.
*   `//src/proxy`: Core proxying logic for TCP, UDP, and HTTP traffic.
*   `//wireguard`: WireGuard device interface and IPC operations.
*   External: `jwt` for token validation, `zerolog` for logging, `prometheus` for metrics.

## Subcomponents
*   `server.go`: Entry point and core server logic.
*   `dataplane.go`: WireGuard and proxy lifecycle management.
*   `store.go`: In-memory peer and IP state storage.
*   `handlers_*.go`: HTTP handlers for auth, tunnels, certs, metrics, and health.
*   `middleware.go`: JWT validation and context helpers.
*   `janitor.go`: Stale tunnel cleanup scheduler.
*   `usage_reporter.go`: Traffic metric aggregation and reporting.
*   `types.go`: Core data structures and interfaces.
*   `test_helpers_test.go`: Test stubs for dataplane isolation.
*   `test_data/`: Build exports for test fixtures (currently empty).