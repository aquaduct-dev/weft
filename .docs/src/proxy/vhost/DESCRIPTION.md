<!-- docdaemon ts:2026-10-15T20:42:13Z hash:c75231ff5418508e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements a name-based virtual host reverse proxy with automatic TLS management, ACME challenge coordination, and HTTP/3 support.

## Overview
The `vhost` package provides a robust infrastructure for hosting multiple domains on a single IP address, handling both HTTP and HTTPS traffic. It integrates Let's Encrypt automation via ACME, ensuring certificates are issued and renewed without manual intervention. The module also supports distributed certificate issuance through peer-to-peer redirection and offers detailed metrics for network traffic monitoring across HTTP/1.1, HTTP/2, and HTTP/3 protocols.

## Deep Dive
### Virtual Host Routing
`VHostProxyManager` orchestrates multiple `VHostProxy` instances, each managing routes for specific hostnames. Requests are dispatched using `PathMatcher` and `HeaderMatcher`, prioritizing the longest matching path prefix to adhere to Gateway-API precedence rules. The system supports plain HTTP and TLS termination, dynamically injecting certificates as they become available.

### ACME Automation & Redirection
Automatic certificate issuance is handled by `AddHostWithACME`, which binds port 80, probes reachability, and fetches certificates asynchronously. In distributed clusters, `acme_redirect.go` coordinates HTTP-01 challenges among peers. It uses a leader-fallback strategy: if a peer is registered for a host, requests are redirected there; otherwise, it falls back to the highest-IP node or local handling, preventing split-brain scenarios during renewal.

### Metering & Transport
The embedded `meter` package tracks byte-level metrics for all connections. For HTTP/1.1 and HTTP/2, it wraps `net.Conn` to count I/O operations. For HTTP/3 (QUIC), it instruments the application layer since per-request connection hooks are unavailable. Additionally, `WGAwareRoundTripper` ensures internal WireGuard addresses are routed through the userspace network stack, with failure tracking to trigger tunnel cleanup.

### Error Handling
Custom logging via `errorlog.go` filters noisy TLS handshake errors from `net/http`, logging them at debug level while surfacing other server errors as warnings. This reduces log spam for internet-exposed ports while maintaining visibility into critical failures.

## Key Interfaces
- `VHostProxy`: Manages routes per hostname, handling request matching and modification.
- `VHostProxyManager`: Orchestrates multiple proxies, manages ACME cache, and handles peer redirections.
- `WGAwareRoundTripper`: Custom transport routing internal WireGuard addresses through a userspace stack.
- `NewMeteredServer`: Creates an `http.Server` configured to extract connection counters from context.
- `countingConn`: A `net.Conn` wrapper that increments atomic counters on I/O operations.
- `countingResponseWriter`: Implements `http.ResponseWriter` to intercept and track header/body writes.

## Dependencies
- `github.com/aquaduct-dev/weft/src/proxy/vhost/meter` (internal metering package)
- `golang.org/x/crypto/acme/autocert` (Let's Encrypt integration)
- `github.com/quic-go/quic-go` (HTTP/3 support)
- `go.uber.org/zap` / `github.com/rs/zerolog` (structured logging)
- `github.com/onsi/ginkgo/v2`, `github.com/onsi/gomega` (testing frameworks)

## Subcomponents
- `BUILD.bazel`: Bazel build configuration for library and test targets.
- `vhost.go`: Core implementation of virtual host proxying and route management.
- `acme_redirect.go`: Coordinates ACME challenge redirection among cluster peers.
- `errorlog.go`: Custom error log writer filtering TLS handshake noise.
- `meter/`: Directory implementing HTTP request/response metering for all protocols.
- `vhost_test.go`: Ginkgo integration tests for routing and TLS management.
- `vhost_race_test.go`: Concurrency regression tests for thread-safety.
- `vhost_suite_test.go`: Ginkgo test suite initialization.
- `acme_redirect_test.go`: Unit tests for ACME challenge redirection logic.
- `certificates_test.go`: Tests for certificate cache parsing and filtering.
- `path_prefix_test.go`: Tests for segment-aware path matching and normalization.
- `probe_test.go`: Tests for ACME challenge validation and security guards.