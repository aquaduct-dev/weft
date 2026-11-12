<!-- docdaemon ts:2026-11-12T09:11:08Z hash:c45c91c34045c241 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `proxy` package implements a multi-protocol tunnel manager that forwards TCP, UDP, and HTTP traffic through WireGuard, featuring automatic TLS management for virtual hosts.

## Overview
This directory provides the core infrastructure for establishing and maintaining network tunnels between public endpoints and internal services. It handles protocol translation, connection lifecycle management, and secure routing via gVisor-based WireGuard integration. The system supports dynamic certificate issuance and distributed ACME challenges to ensure availability in round-robin DNS environments.

## Deep Dive
### Core Proxy Logic
`ProxyManager` orchestrates active tunnels, enforcing uniqueness and delegating to specific implementations. `TCPProxy` uses a sliding-window failure tracker to prevent teardown during transient upstream outages. `UDPProxy` manages stateful sessions using source-address-keyed maps with mutex protection to avoid race conditions. Both types utilize `WGAware` wrappers to route traffic through the gVisor NetStack when targeting internal subnets.

### Virtual Host Management
The `vhost` subdirectory handles HTTP/HTTPS routing with segment-aware prefix matching. It supports automatic TLS via Let's Encrypt ACME, distributing HTTP-01 challenges across sibling bastions to handle round-robin DNS scenarios. The proxy filters TLS handshake errors to reduce log noise and validates challenge targets to prevent SSRF attacks. HTTP/3 (QUIC) is supported for public listeners, while internal routes default to HTTP/1.1.

### Resilience & Metering
Recent updates addressed panics in `WGAwareUDPConn.ReadFromUDP` when gVisor connections close, ensuring graceful error handling instead of crashes. Byte-metering components track traffic at both connection and application layers for accurate billing. The ACME reachability probe now queries zone nameservers directly to bypass cached NXDOMAIN records, preventing certificate issuance failures for new hosts.

## Key Interfaces
*   `ProxyManager`: Central coordinator for creating, starting, and stopping proxy instances.
*   `Proxy`: Interface defining lifecycle methods (`Close`, `Name`) and metrics (`BytesTx`, `BytesRx`).
*   `VHostProxyManager`: Manages virtual host routes, certificate caching, and status endpoints.
*   `WGAwareRoundTripper`: Routes HTTP upstream traffic through WireGuard for internal targets.
*   `PathMatcher`: Performs segment-aware prefix matching for route selection.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Let's Encrypt integration.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   Standard library: `net/http`, `crypto/tls`, `sync`.

## Subcomponents
*   `proxy.go`: Core proxy logic and manager implementation.
*   `types.go`: Interface definitions and WireGuard-aware connection wrappers.
*   `BUILD.bazel`: Bazel build targets for library and tests.
*   `proxy_suite_test.go`: Ginkgo test suite initialization.
*   `proxy_test.go`: Integration tests for tunnel creation and conflict detection.
*   `vhost/`: Virtual host reverse proxy implementation.
*   `vhost/vhost.go`: Core routing and TLS configuration.
*   `vhost/challenge_proxy.go`: Distributed ACME challenge forwarding.
*   `vhost/errorlog.go`: Filtered HTTP error logging.
*   `vhost/meter/`: Byte-metering components for HTTP/1.1, 2, and 3.