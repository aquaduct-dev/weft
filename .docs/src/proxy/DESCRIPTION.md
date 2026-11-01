<!-- docdaemon ts:2026-11-01T18:06:03Z hash:154f25d2a7bc078e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `proxy` package implements a multi-protocol tunnel manager that forwards TCP, UDP, and HTTP traffic through WireGuard, handling lifecycle management, conflict detection, and automatic TLS provisioning.

## Overview
This directory serves as the core transport layer for the bastion nodes, abstracting the complexity of network stack operations behind a unified `ProxyManager`. It supports dynamic route registration, allowing multiple virtual hosts to share a single IP address while maintaining isolated traffic flows. The system is designed to be resilient against transient upstream failures and concurrent session management, ensuring stable connectivity for both stream-oriented and datagram protocols.

## Deep Dive
### Protocol Forwarding
The `ProxyManager` orchestrates `TCPProxy`, `UDPProxy`, and `VHostRouteProxy` instances. TCP tunnels use a sliding-window failure tracker to prevent teardown during brief outages, while UDP sessions are keyed by source address and protected against concurrent map writes. All connections utilize `WGAware` wrappers to route traffic through the gVisor NetStack when targeting the WireGuard subnet, falling back to standard transports otherwise.

### Virtual Host Routing
HTTP/HTTPS traffic is handled by delegating to the `vhost` subpackage, which manages name-based routing, path modifiers, and ACME-based certificate issuance. Routes are matched using longest-prefix logic for paths and strict hostname matching. The system supports distributed HTTP-01 challenges across cluster peers to handle round-robin DNS scenarios, ensuring Let's Encrypt validations succeed regardless of which node receives the request.

### Resilience and Observability
Metrics are tracked at both connection and application layers, with specific handling for HTTP/3 streaming data. Error logging filters noisy TLS handshake failures to debug level, surfacing only critical server errors. Recent fixes addressed panics in `WGAwareUDPConn.ReadFromUDP` when underlying connections closed, ensuring graceful error propagation instead of crashes during session termination.

## Key Interfaces
*   `ProxyManager`: Central coordinator for creating, starting, and managing proxy instances.
*   `Proxy`: Interface defining lifecycle methods (`Close`, `Name`) and metrics (`BytesTx`, `BytesRx`).
*   `TCPProxy`: Manages TCP listeners and upstream dialing with failure tracking.
*   `UDPProxy`: Handles UDP sessions via source-address-keyed maps and response goroutines.
*   `VHostRouteProxy`: Registers HTTP routes with the VHost manager and handles TLS configuration.
*   `WGAwareUDPConn`: Wrapper for UDP connections that integrates with the gVisor NetStack.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Let's Encrypt certificate management.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   `github.com/ginkgo-ginkgo/ginkgo/v2` & `gomega`: Testing framework.
*   Standard library: `net`, `crypto/tls`, `sync`, `io`.

## Subcomponents
*   `proxy.go`: Core proxy implementations and manager logic.
*   `types.go`: Proxy interface definitions and WireGuard-aware connection wrappers.
*   `BUILD.bazel`: Bazel build targets for library and tests.
*   `proxy_suite_test.go`: Ginkgo test suite initialization.
*   `proxy_test.go`: Integration tests for protocol forwarding and conflict detection.
*   `vhost/`: Virtual host reverse proxy implementation.