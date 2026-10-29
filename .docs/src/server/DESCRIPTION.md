<!-- docdaemon ts:2026-10-29T21:06:07Z hash:c2e2818bd2922a0e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src/server` package implements the Weft control plane, managing WireGuard tunnel lifecycle, authentication, and observability.

## Overview
This directory contains the HTTP server that orchestrates client connections to the Weft mesh network. It handles JWT-based challenge-response authentication, provisions WireGuard peers with dynamic IP allocation, and manages background tasks like health-check janitors and usage reporting. The architecture separates HTTP handlers from core logic to facilitate modular testing and security hardening.

## Deep Dive
### Authentication & Security
The server enforces strict access controls using a multi-step challenge-response flow. Clients must exchange encrypted challenges for signed JWTs before accessing protected endpoints. Middleware validates these tokens, ensuring the subject claim matches the requested tunnel name to prevent hijacking. Metrics endpoints use constant-time comparison for secret validation to mitigate timing attacks.

### Tunnel Lifecycle Management
Core connectivity is handled by `handlers_tunnel.go`, which coordinates peer creation, IP allocation, and proxy startup. To maintain network stability during high churn, `dataplane.go` performs incremental WireGuard configuration updates rather than full device rebuilds. This preserves learned roaming endpoints for active tunnels when others are removed, preventing traffic disruption.

### Observability & Maintenance
Operational health is monitored via Prometheus-compatible metrics and JSON status endpoints. A background `Janitor` periodically sweeps the store to remove tunnels that have failed health checks, preventing resource leaks. An `HTTPUsageReporter` aggregates traffic statistics and sends them to external monitoring systems asynchronously.

## Key Interfaces
- `Server`: Main struct holding HTTP listener, store, dataplane, and secrets.
- `TunnelDataplane`: Manages WireGuard device state and proxy routing.
- `InMemoryTunnelStore`: Thread-safe storage for peer metadata and IP allocations.
- `Janitor`: Background worker for cleaning up stale tunnels.
- `HTTPUsageReporter`: Periodic reporter for tunnel traffic statistics.

## Dependencies
- Internal packages: `crypto`, `proxy`, `wireguard`, `version`.
- External libraries: `github.com/golang-jwt/jwt/v4`, `google.golang.org/grpc`, `prometheus/client_golang`.

## Subcomponents
- `server.go`: Server initialization and TLS setup.
- `middleware.go`: JWT validation middleware.
- `handlers_auth.go`: Challenge-response login logic.
- `handlers_tunnel.go`: Connect/Shutdown endpoint handlers.
- `handlers_health.go`: Health check processing.
- `handlers_metrics.go`: Prometheus and JSON metrics.
- `handlers_certificates.go`: ACME certificate status.
- `handlers_version.go`: Build metadata endpoint.
- `dataplane.go`: WireGuard and proxy management.
- `store.go`: In-memory peer and IP storage.
- `janitor.go`: Stale tunnel cleanup.
- `usage_reporter.go`: Traffic reporting.
- `types.go`: Core data structures and interfaces.
- `test_helpers_test.go`: Test stubs.
- `test_data/`: TLS fixture labels.