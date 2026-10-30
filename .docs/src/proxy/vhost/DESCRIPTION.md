<!-- docdaemon ts:2026-10-30T02:43:22Z hash:f16683e892d4008d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
Manages virtual hosting, TLS certificate issuance via ACME, and HTTP/3 termination for the proxy.

## Overview
This package implements a name-based virtual host reverse proxy that handles dynamic route registration, TLS termination, and automated certificate management. It supports multiple traffic modes including plain HTTP, static TLS, and ACME-automated TLS, ensuring robust certificate lifecycle management even in distributed environments with round-robin DNS. The system also provides accurate byte-metering across HTTP/1.1, HTTP/2, and HTTP/3 protocols to support billing and monitoring policies.

## Deep Dive
### Virtual Host Routing
`VHostProxy` manages routes per hostname using longest-prefix matching to resolve overlapping paths. It applies matchers (path, header, query) and modifiers (header injection, redirects, path stripping). The `WGAwareRoundTripper` routes upstream requests through WireGuard for internal targets, while standard transport is used otherwise.

### ACME Certificate Management
The `VHostProxyManager` coordinates ACME issuance, caching certificates locally and handling failures gracefully. To support distributed deployments, it implements a challenge proxy that relays HTTP-01 challenges to sibling nodes holding the token, preventing redirect loops and ensuring Let's Encrypt validators can reach the correct node regardless of DNS distribution.

### Metering and Observability
The embedded `meter` package tracks byte traffic for both completed and in-flight requests. For TCP-based protocols, it wraps connections to count bytes at the network layer. For HTTP/3, it instruments the application layer to capture body sizes and headers, ensuring accurate metrics during streaming transfers.

### Error Handling
A custom error log writer filters noisy TLS handshake errors from `net/http`, logging them at debug level while surfacing other server errors as warnings. This reduces log spam on internet-exposed ports while maintaining visibility into critical failures.

## Key Interfaces
*   `VHostProxy`: Manages routes and TLS configuration for a single hostname.
*   `VHostProxyManager`: Coordinates multiple proxies, ACME listeners, and certificate caching.
*   `MeteredServer`: Wraps `http.Server` to provide TLS counting and context injection.
*   `PathMatcher`: Performs segment-aware prefix matching for route selection.
*   `httpErrorLogWriter`: Routes net/http errors through zerolog with filtering logic.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Let's Encrypt integration.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   Standard library: `net/http`, `crypto/tls`, `sync`.

## Subcomponents
*   `vhost.go`: Core proxy implementation and manager.
*   `challenge_proxy.go`: Distributed HTTP-01 challenge relay logic.
*   `errorlog.go`: Custom HTTP error logger.
*   `meter/`: Byte-metering components for all HTTP versions.
*   `*_test.go`: Comprehensive test suite for routing, ACME, and concurrency.