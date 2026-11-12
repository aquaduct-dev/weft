<!-- docdaemon ts:2026-11-12T09:10:40Z hash:0f7b506eb9a60c57 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements a name-based virtual host reverse proxy with automatic TLS termination, HTTP/2 and HTTP/3 support, and distributed ACME challenge handling.

## Overview
The `vhost` package manages dynamic route registration and certificate lifecycle for multiple hosts on shared ports. It supports static PEM certificates, Let's Encrypt via ACME, and plain HTTP, ensuring robust operation in round-robin DNS environments by distributing HTTP-01 challenges across sibling bastions. The system integrates with WireGuard for internal traffic routing and provides accurate byte-metering for billing and monitoring across all supported protocols.

## Deep Dive
### Virtual Host Routing
`VHostProxy` dispatches requests to `Route` objects based on path prefix, header, query, or method matchers. Path matching is segment-aware to prevent collisions (e.g., `/api` vs `/apifoo`) and normalizes dot-segments. The longest matching prefix wins, adhering to Gateway-API precedence rules.

### ACME Challenge Distribution
To support round-robin DNS, the proxy implements a distributed HTTP-01 challenge proxy. If a node cannot answer locally, it queries siblings via `acme.FetchChallengeFromPeers`. Requests marked with `NoProxyParam` are not forwarded further, preventing infinite loops. Challenges for unmanaged hosts fall through to the backend if configured. The listener remains open even without active hosts to allow reachability probes from peers.

### Protocol Support & Metering
The proxy negotiates HTTP/2 over TLS and serves HTTP/3 (QUIC) on UDP for public listeners. Internal WireGuard routes use HTTP/1.1. The `meter` sub-package tracks byte traffic at the connection level for HTTP/1.1/2 and application layer for HTTP/3, ensuring accurate metrics for long-lived streaming requests.

### Security & Error Handling
TLS handshake errors are filtered to debug level to reduce log noise. The proxy validates ACME challenge targets to prevent SSRF, rejecting loopback and private IPs. WireGuard-aware transport restricts userspace stack usage to specific internal IP ranges.

## Key Interfaces
*   `VHostProxyManager`: Coordinates multiple proxies, certificate caching, and status endpoints.
*   `VHostProxy`: Manages routing, TLS configs, and protocol negotiation for a single listener.
*   `MeteredServer`: Wraps `http.Server` to provide TLS counting and context injection.
*   `PathMatcher`: Performs segment-aware prefix matching for route selection.
*   `WGAwareRoundTripper`: Routes upstream traffic through WireGuard for internal targets.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Let's Encrypt integration.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   Standard library: `net/http`, `crypto/tls`, `sync`.

## Subcomponents
*   `vhost.go`: Core proxy implementation and routing logic.
*   `challenge_proxy.go`: Distributed HTTP-01 challenge forwarding.
*   `errorlog.go`: Filtered HTTP error logging.
*   `meter/`: Byte-metering components for HTTP/1.1, 2, and 3.
*   `*_test.go`: Ginkgo/Gomega test suite covering race conditions, ACME failures, and metering.