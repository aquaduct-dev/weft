<!-- docdaemon ts:2026-10-29T21:04:57Z hash:63aa0a251abf1dae model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements a name-based virtual host reverse proxy with TLS termination, ACME certificate management, and HTTP/3 support.

## Overview
The `vhost` package manages multiple virtual hosts on shared ports, routing requests based on hostname, path, and other headers. It handles automatic certificate issuance via Let's Encrypt, including distributed challenge validation for round-robin DNS setups. The system also tracks byte traffic across HTTP/1.1, HTTP/2, and HTTP/3 protocols to support accurate monitoring and billing.

## Deep Dive
### Virtual Host Routing
`VHostProxy` maintains per-hostname routes with segment-aware prefix matching. Longest-prefix precedence ensures specific paths (e.g., `/media`) are not shadowed by catch-alls (`/`). Routes apply modifiers like header injection or path stripping before forwarding to upstreams. WireGuard integration allows routing to internal `10.1.*` addresses with automatic tunnel cleanup on failure.

### ACME Certificate Management
Automatic TLS certificates are issued using `autocert`. To support cluster deployments where validators may hit any node, the system proxies HTTP-01 challenges to peers holding the key authorization, preventing redirect loops and ensuring successful validation. Probes DNS-resolved IPs before issuance to verify reachability, requiring a majority of records to respond in round-robin scenarios.

### Traffic Metering
The `meter` subpackage provides transparent byte-metering for completed and in-flight requests. For TCP-based protocols, it wraps connections to count raw I/O. For HTTP/3 over QUIC, it instruments request bodies and response writers at the application layer. Active connection tracking ensures real-time accuracy for long-lived transfers.

### Protocol Support
Public listeners default to HTTP/2 and HTTP/3 (QUIC), falling back to HTTP/1.1. WebSockets are handled over HTTP/1.1 to avoid compatibility issues with Extended CONNECT. The `WGAwareRoundTripper` optimizes transport selection, using the userspace WireGuard stack only for internal targets when a device is available.

## Key Interfaces
*   `VHostProxy`: Manages routes and TLS configuration for a single hostname.
*   `VHostProxyManager`: Coordinates multiple proxies and ACME state across ports.
*   `MeteredServer`: Wraps `http.Server` to provide TLS counting and context injection.
*   `MeteredHTTPHandler`: Aggregates traffic metrics and exposes `BytesRx()`/`BytesTx()`.
*   `PathMatcher`: Performs segment-aware prefix matching for route selection.
*   `PathPrefixModifier`: Strips prefixes from paths while preserving segment boundaries.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Automatic certificate management.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   Internal packages: `acme`, `metrics`, `tunnel`, `wireguard`.

## Subcomponents
*   `vhost.go`: Core proxy implementation and manager logic.
*   `challenge_proxy.go`: Distributed HTTP-01 challenge handling.
*   `errorlog.go`: Structured error logging for net/http.
*   `meter/`: Byte metering for HTTP/1.1, HTTP/2, and HTTP/3.
*   `*_test.go`: Unit, integration, and race condition tests.