<!-- docdaemon ts:2026-10-09T01:41:35Z hash:0d4174f91dc75c91 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements a multi-host reverse proxy with dynamic TLS termination, ACME automation, and HTTP/3 support.

## Overview
The `vhost` package serves as the network edge for the proxy infrastructure, terminating TLS and routing traffic to upstream services based on virtual host rules. It supports HTTP/1.1, HTTP/2, and HTTP/3 (QUIC), providing automatic certificate management via Let's Encrypt ACME challenges. The module ensures high availability through peer redirect mechanisms and maintains accurate network metrics across all supported protocols.

## Deep Dive
### Virtual Host Routing
`VHostProxyManager` orchestrates multiple proxies, mapping incoming requests to specific routes using path prefixes, headers, and methods. The longest matching prefix wins, ensuring precise control over sub-path routing. Requests are forwarded via `httputil.ReverseProxy`, with optional WireGuard-aware transport selection.

### ACME Automation & Peer Redirects
Automatic certificate issuance is handled by integrating with `autocert`. To prevent split-brain scenarios during DNS propagation, the system uses a leader-fallback strategy. If a peer registers itself as the authoritative responder for a host, other nodes redirect ACME challenge requests to that peer. This coordination prevents race conditions and ensures successful validation regardless of which node receives the initial query.

### Metering Infrastructure
Network traffic volume is tracked at both connection and application layers. For HTTP/1.1 and HTTP/2, `countingConn` wraps `net.Conn` to increment atomic counters on I/O operations. HTTP/3 metering operates at the application layer via `countingResponseWriter`, intercepting body writes since QUIC lacks per-request connection hooks. Global metrics aggregate these counts for monitoring.

### Error Handling
A custom `httpErrorLogWriter` filters noisy TLS handshake errors from standard net/http logs, sending them to debug level while surfacing other server errors as warnings. This reduces log spam without hiding critical issues.

## Key Interfaces
- `VHostProxy`: Manages routes per hostname, handling TCP and UDP listeners.
- `VHostProxyManager`: Orchestrates multiple proxies, ACME issuance, and peer redirects.
- `Route`: Combines matchers (path, header) and modifiers (redirects).
- `AddHostWithACME`: Registers a host for automatic Let's Encrypt issuance.
- `CanPassACMEChallenge`: Validates DNS resolution and firewall accessibility.
- `NewMeteredServer`: Creates an http.Server configured for connection-level metering.
- `MeteredHTTPHandler`: Adapter tracking per-request metrics and aggregating global counters.
- `countingConn`: net.Conn wrapper incrementing atomic counters on I/O.
- `countingResponseWriter`: Intercepts header/body writes for HTTP/3 metering.

## Dependencies
- github.com/aquaduct-dev/weft/src/proxy/vhost/meter
- golang.org/x/crypto/acme/autocert
- github.com/quic-go/quic-go
- github.com/google/ginkgo/v2
- github.com/onsi/gomega
- go.uber.org/zap (zerolog integration)

## Subcomponents
- acme_redirect.go: Coordinates HTTP-01 ACME challenge redirection among cluster peers.
- errorlog.go: Custom http.ErrorLog writer filtering TLS handshake noise.
- vhost.go: Core implementation of VHostProxy and VHostProxyManager.
- meter/: HTTP request/response metering for HTTP/1.1, 2, and 3.
- acme_redirect_test.go: Unit tests for ACME challenge redirection logic.
- certificates_test.go: Tests for ListCertificates parsing and filtering.
- path_prefix_test.go: Tests for segment-aware path matching and stripping.
- probe_test.go: Tests for ACME challenge validation and host registration.
- vhost_race_test.go: Concurrency regression tests for data races.
- vhost_suite_test.go: Ginkgo test suite initialization.
- vhost_test.go: Integration tests for routing, TLS, and transport logic.