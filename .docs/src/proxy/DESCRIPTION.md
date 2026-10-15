<!-- docdaemon ts:2026-10-15T20:42:34Z hash:07d08b3dea068ad7 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `proxy` package orchestrates the lifecycle, creation, and routing of TCP, UDP, and HTTP/HTTPS virtual host proxies.

## Overview
This directory implements the core proxying infrastructure for the Weft project, managing tunnels that forward traffic between local endpoints and remote destinations. It supports transparent layer-4 forwarding for TCP and UDP, as well as layer-7 HTTP/HTTPS routing with automatic TLS management via ACME. The system integrates with WireGuard to route internal traffic through a userspace network stack while maintaining strict conflict detection and concurrency safety.

## Deep Dive
### Proxy Lifecycle Management
`ProxyManager` serves as the central controller, maintaining a registry of active proxies keyed by name. It prevents duplicate configurations and conflicting port bindings. The manager delegates specific protocol handling to specialized instances (`TCPProxy`, `UDPProxy`, `VHostRouteProxy`) and provides methods to start, stop, and query traffic statistics for all active tunnels.

### Protocol-Specific Handling
TCP proxying uses failure tracking to automatically clean up tunnels after sustained upstream dial failures, ensuring resilience against transient outages. UDP proxying maintains per-source-address sessions in a mutex-protected map to prevent concurrent writes, spawning response goroutines only when new source addresses are detected. This design minimizes resource usage while supporting high-concurrency scenarios.

### Virtual Host Routing
HTTP/HTTPS routing is handled by delegating to the `vhost` sub-package, which manages name-based virtual hosts. It parses URL fragments for matchers (query params, headers) and modifiers (redirects), supporting path prefix rewriting and header manipulation. Automatic TLS certificate issuance is coordinated via ACME, with distributed challenge redirection among cluster peers to prevent split-brain scenarios during renewal.

### WireGuard Integration
All networking utilities are "WireGuard-aware," automatically detecting if an address belongs to the WireGuard subnet and routing traffic through the `gvisor` userspace stack or standard OS sockets accordingly. This abstraction allows the proxy logic to remain agnostic of the underlying transport mechanism while ensuring correct packet delivery.

## Key Interfaces
*   `ProxyManager`: Central controller for creating, starting, and closing proxy tunnels.
*   `Proxy`: Interface defining contract for lifecycle, conflict detection, and metrics.
*   `WGAwareTCPListen/Dial`: Functions that route TCP connections based on WireGuard subnet awareness.
*   `WGAwareUDPConn`: Dual-mode connection wrapper selecting between standard and WireGuard sockets.
*   `NewMeteredServer`: Factory for HTTP servers configured to extract connection counters from context.

## Dependencies
*   `github.com/aquaduct-dev/weft/src/proxy/vhost` (internal virtual host handling)
*   `github.com/aquaduct-dev/weft/src/proxy/meter` (internal metering)
*   `go.uber.org/zap` / `github.com/rs/zerolog` (structured logging)
*   `github.com/quic-go/quic-go` (HTTP/3 support)
*   `golang.org/x/crypto/acme/autocert` (Let's Encrypt integration)
*   `github.com/onsi/ginkgo/v2`, `github.com/onsi/gomega` (testing frameworks)

## Subcomponents
*   `BUILD.bazel`: Bazel build configuration for library and test targets.
*   `proxy.go`: Core implementation of `ProxyManager` and tunnel orchestration.
*   `types.go`: Core abstractions, interfaces, and WireGuard-aware networking utilities.
*   `proxy_suite_test.go`: Ginkgo test suite initialization.
*   `proxy_test.go`: Integration and unit tests for proxy functionality.
*   `vhost/`: Directory implementing virtual host reverse proxy and ACME automation.