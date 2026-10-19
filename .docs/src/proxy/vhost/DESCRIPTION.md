<!-- docdaemon ts:2026-10-19T23:26:48Z hash:881bd28d1cb93bf0 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements a name-based virtual host reverse proxy with automatic TLS management, ACME challenge coordination, and HTTP/3 support.

## Overview
The `vhost` package serves as the core traffic termination layer for the proxy, managing multiple hosts on shared ports. It handles dynamic certificate issuance via Let's Encrypt, coordinates cluster-wide ACME challenges to prevent split-brain scenarios, and supports modern protocols including HTTP/2 and HTTP/3. The system ensures secure, efficient routing of incoming requests to upstream services while maintaining accurate traffic metrics.

## Deep Dive
### Virtual Host Routing
`VHostProxy` manages route selection based on path prefixes, headers, and methods. It prioritizes the longest matching prefix to prevent catch-all routes from shadowing specific endpoints. Path modifiers strip configured prefixes while preserving segment boundaries and normalizing dot-segments to ensure clean upstream requests.

### TLS and ACME Management
The proxy supports static TLS certificates and dynamic ACME issuance. For ACME, it probes public IPs to verify reachability before binding port 80, ensuring race-free challenge validation. A leader-fallback strategy coordinates HTTP-01 redirects among cluster peers, using peer registrations or highest-IP DNS resolution to direct challenges to the correct node. Failed issuances are recorded and exposed via API, allowing operators to monitor certificate health.

### Protocol Support and Metering
HTTP/2 is enabled by default for TLS listeners, with HTTP/3 served on a separate UDP listener for public addresses. Internal WireGuard routes remain on HTTP/1.1. The `meter` subpackage provides transparent byte-metering across all protocols, wrapping connections and response writers to track in-flight and completed request volumes accurately.

### Error Handling and Logging
Custom error log writers filter noisy TLS handshake failures to debug level while surfacing other server errors as warnings. This reduces log spam from internet-exposed ports without hiding critical issues. Concurrency safety is enforced through mutexes protecting internal maps, verified by regression tests against data races.

## Key Interfaces
- `VHostProxy`: Manages routing, TLS configuration, and host registration.
- `VHostProxyManager`: Coordinates multiple proxies and ACME state.
- `MeteredServer`: Wraps `http.Server` to inject connection context and metering.
- `MeteredHTTPHandler`: Aggregates traffic metrics and exposes byte counts.
- `countingConn`: Wraps `net.Conn` to track raw byte I/O atomically.
- `countingResponseWriter`: Implements `http.ResponseWriter` to capture header and body sizes.

## Dependencies
- `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
- `golang.org/x/crypto/acme/autocert`: Automatic certificate issuance.
- `go.uber.org/zap`: Structured logging integration.
- Standard library: `net/http`, `crypto/tls`, `sync`, `io`.

## Subcomponents
- `acme_redirect.go`: ACME challenge redirection logic.
- `errorlog.go`: Custom HTTP error logging.
- `vhost.go`: Core proxy implementation.
- `meter/`: Traffic metering components.
- `*_test.go`: Unit and integration tests.