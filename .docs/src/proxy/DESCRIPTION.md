<!-- docdaemon ts:2026-10-30T02:44:19Z hash:c19cbbb7d8c74886 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `proxy` package implements a multi-protocol tunnel manager that forwards TCP, UDP, and HTTP traffic through WireGuard, handling lifecycle, conflict resolution, and virtual host routing.

## Overview
This directory provides the core infrastructure for establishing and maintaining network tunnels between public endpoints and internal targets. It abstracts away the complexity of protocol translation, connection multiplexing, and TLS management, allowing higher-level components to register proxies by name and scheme. The system ensures robust operation in distributed environments by handling transient failures, concurrent access, and automated certificate issuance.

## Deep Dive
### Proxy Orchestration
`ProxyManager` acts as the central coordinator, mapping proxy names to concrete implementations (`TCP`, `UDP`, `VHost`). It enforces uniqueness constraints, returning specific errors for conflicts to prevent duplicate tunnel registration. The manager delegates HTTP/HTTPS traffic to the `vhost` subpackage, which handles complex routing logic.

### Protocol Forwarding
TCP and UDP proxies manage stream and session lifecycles respectively. TCP forwarding uses a sliding-window failure tracker to tolerate brief upstream outages without tearing down the tunnel. UDP sessions are keyed by source address, with dedicated goroutines handling upstream reads to prevent race conditions on shared maps. Both protocols utilize WireGuard-aware dialers to route traffic through the gVisor netstack when targeting internal subnets.

### Virtual Host Routing
HTTP/HTTPS traffic is handled by `VHostRouteProxy`, which registers routes with the `VHostProxyManager`. This component supports longest-prefix matching, header modifiers, and path rewrites via URL fragments. It manages TLS certificates using ACME for automatic issuance or static PEM data, ensuring secure termination for external clients.

### Resilience and Observability
The system includes metrics tracking for bytes transmitted and received across all proxy types. Error handling has been hardened to prevent panics during connection closure, particularly in WireGuard paths where nil addresses may be returned. A custom error logger filters noisy TLS handshake errors to reduce log spam while preserving visibility into critical failures.

## Key Interfaces
*   `Proxy`: Standard interface for lifecycle management, identification, and metrics.
*   `ProxyManager`: Orchestrates active proxies and resolves conflicts.
*   `VHostProxyManager`: Coordinates virtual hosts, ACME issuance, and challenge relays.
*   `WGAwareUDPConn`: WireGuard-aware UDP connection wrapper with safe read handling.
*   `parseModifiers`: Utility function for extracting header modifications from URL fragments.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Let's Encrypt integration.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   Internal packages: `util`, `vhost`, `vhost/meter`.

## Subcomponents
*   `proxy.go`: Core proxy implementations and manager logic.
*   `types.go`: Interface definitions and WireGuard-aware connection wrappers.
*   `BUILD.bazel`: Bazel build targets for library and tests.
*   `proxy_suite_test.go`: Ginkgo test suite initialization.
*   `proxy_test.go`: Integration tests for tunnel creation and forwarding.
*   `vhost/`: Virtual host routing and TLS management.