<!-- docdaemon ts:2026-10-30T02:44:19Z hash:eeb7ede0541caab5 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src/server` package implements the Weft control plane, managing WireGuard tunnel lifecycle, authentication, and observability via an HTTP API.

## Overview
This directory contains the core server logic that orchestrates client connections, maintains tunnel state, and exposes metrics. It handles the full request lifecycle from JWT-based challenge-response authentication to dynamic IP allocation and reverse proxy management. Background workers ensure system hygiene by cleaning up stale tunnels and reporting usage statistics.

## Deep Dive
### Authentication and Security
The server enforces strict access controls using a multi-step challenge-response flow. Clients must exchange encrypted challenges for signed JWTs, which are validated against a connection secret. Middleware ensures all protected routes require valid tokens, while constant-time comparisons prevent timing attacks on secrets. The `/version` endpoint remains public for client compatibility checks without exposing sensitive data.

### Tunnel Lifecycle Management
Tunnel establishment involves validating JWT claims, allocating IPs from a subnet pool, and configuring the WireGuard dataplane. The `handlers_tunnel.go` module coordinates these steps, rolling back changes if intermediate failures occur. Removal of a tunnel triggers cleanup of proxies, IP releases, and peer deletion. Crucially, WireGuard configuration updates are incremental to preserve learned roaming endpoints, preventing disruption during churn.

### Observability and Maintenance
Operational health is monitored through Prometheus-compatible metrics and JSON status reports. A background janitor periodically sweeps the store to remove tunnels that have not reported health checks within a threshold, preventing resource leaks. An HTTP usage reporter aggregates traffic counters and sends them to external endpoints asynchronously. ACME certificate issuance errors are surfaced via a dedicated endpoint to aid in debugging TLS provisioning issues.

## Key Interfaces
- `Server`: Main struct holding HTTP listener, store, dataplane, and secrets.
- `Dataplane`: Interface for WireGuard configuration and proxy lifecycle management.
- `TunnelStore`: Abstraction for peer state and IP address allocation.
- `Janitor`: Background worker for removing stale tunnels.
- `HTTPUsageReporter`: Component for aggregating and sending traffic statistics.

## Dependencies
- Internal packages: `crypto`, `proxy`, `wireguard`, `version`.
- External libraries: `prometheus`, `jwt-go`, `autocert`.

## Subcomponents
- `dataplane.go`: WireGuard and proxy management implementation.
- `handlers_*.go`: HTTP handlers for auth, certs, health, metrics, tunnels, and version.
- `middleware.go`: JWT validation middleware and context helpers.
- `server.go`: Server initialization and route registration.
- `store.go`: In-memory peer and IP address storage.
- `janitor.go`: Stale tunnel cleanup logic.
- `usage_reporter.go`: Traffic statistics reporting.
- `types.go`: Core interfaces and data structures.
- `test_helpers_test.go`: Mock dataplane for unit tests.
- `test_data/`: Directory for test fixtures (currently empty).