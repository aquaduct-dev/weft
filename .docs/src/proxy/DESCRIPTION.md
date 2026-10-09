<!-- docdaemon ts:2026-10-09T01:41:57Z hash:a5394db5a7ef4fdd model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `proxy` package orchestrates the lifecycle, creation, and routing of TCP, UDP, and HTTP/HTTPS virtual host proxies.

## Overview
This directory implements the core proxying infrastructure for the Weft project, managing a registry of active tunnels and delegating traffic to specific protocol handlers. It integrates with WireGuard’s netstack to provide transparent layer-4 forwarding while supporting complex layer-7 HTTP/HTTPS routing through the embedded `vhost` sub-package. The system ensures concurrency safety, handles automatic TLS certificate issuance via ACME, and tracks network metrics across all supported protocols.

## Deep Dive
### Proxy Management
`ProxyManager` serves as the central controller, maintaining a thread-safe registry of named proxies. It prevents configuration conflicts by validating port bindings and duplicate names before instantiation. The manager delegates specific protocol handling to `TCPProxy`, `UDPProxy`, and `VHostRouteProxy` instances, ensuring clean separation of concerns.

### Protocol Handling
TCP proxying utilizes `WGAwareTCPListen/Dial` to route connections through either standard or WireGuard-aware network stacks, including failure tracking to auto-clean up unstable tunnels. UDP proxying maintains per-source-address sessions in a mutex-protected map, spawning response goroutines only for new sources to minimize resource usage. Both implementations abstract away the underlying transport differences.

### Virtual Host Routing
HTTP/HTTPS traffic is routed through the `vhost` package, which supports dynamic TLS termination and ACME automation. Routes are defined by matchers (path prefixes, headers) and modifiers (redirects), with longest-prefix matching ensuring precise control. The system includes peer redirect mechanisms for ACME challenges to prevent split-brain scenarios during DNS propagation.

### Metering and Observability
Traffic volume is tracked at both connection and application layers using atomic counters. For HTTP/1.1 and 2, `countingConn` wraps connections to increment counters on I/O. HTTP/3 metering intercepts body writes via `countingResponseWriter`. Global metrics aggregate these counts for monitoring, while custom error log writers filter noisy TLS handshake errors to reduce log spam.

## Key Interfaces
*   `ProxyManager`: Central controller for creating, starting, and closing proxy tunnels.
*   `Proxy`: Interface defining lifecycle (`Close`), conflict detection (`Conflicts`), and metrics (`BytesTx`, `BytesRx`).
*   `TCPProxy`: Transparent TCP layer-4 forwarder with failure tracking.
*   `UDPProxy`: UDP forwarder using dual-mode socket selection based on destination IP.
*   `VHostRouteProxy`: Layer-7 HTTP/HTTPS router delegating to the VHost manager.
*   `WGAwareTCPDial` / `WGAwareUDPDial`: Functions that automatically detect WireGuard subnet membership.

## Dependencies
*   github.com/aquaduct-dev/weft/src/proxy/vhost
*   github.com/aquaduct-dev/weft/src/proxy/vhost/meter
*   github.com/google/ginkgo/v2
*   github.com/onsi/gomega
*   go.uber.org/zap
*   golang.org/x/crypto/acme/autocert
*   github.com/quic-go/quic-go

## Subcomponents
*   BUILD.bazel
*   proxy.go
*   proxy_suite_test.go
*   proxy_test.go
*   types.go
*   vhost/