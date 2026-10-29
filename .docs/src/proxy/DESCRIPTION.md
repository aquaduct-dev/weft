<!-- docdaemon ts:2026-10-29T21:06:06Z hash:93933468bffbfa4d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `proxy` package implements protocol-agnostic tunneling for TCP, UDP, and HTTP/HTTPS traffic with WireGuard integration.

## Overview
This directory orchestrates network proxies that forward traffic between public listeners and internal targets. It manages the lifecycle of tunnels, handles connection state, and ensures resilience against transient failures. The system supports automatic TLS certificate management via ACME and provides detailed metrics for billing and monitoring.

## Deep Dive
### Core Proxy Logic
`ProxyManager` coordinates active instances, enforcing uniqueness to prevent conflicts. It delegates routing decisions based on source and destination schemes, instantiating specific proxy types for TCP, UDP, or virtual hosts. TCP connections use a sliding-window failure tracker to avoid premature teardown during brief outages, while UDP sessions are keyed by source address to manage concurrent streams safely.

### Virtual Host Management
The `vhost` subdirectory handles HTTP/HTTPS traffic through name-based routing. It supports longest-prefix matching to ensure specific paths are not shadowed by catch-all routes. Automatic TLS certificates are issued via Let's Encrypt, with distributed challenge validation to support round-robin DNS setups where validators may hit any node in a cluster.

### WireGuard Integration
Traffic destined for internal subnets is routed through the gVisor NetStack using `WGAware` wrappers. These wrappers detect when a connection should traverse the WireGuard interface, optimizing transport selection. Recent fixes ensure graceful error handling when underlying connections close, preventing panics during session termination.

### Metrics and Monitoring
Byte traffic is metered across all protocols, including HTTP/3 over QUIC. The system tracks both completed and in-flight requests to provide accurate real-time usage data. This metering supports billing logic and operational visibility into tunnel health.

## Key Interfaces
*   `Proxy`: Standardizes traffic forwarding, lifecycle management, and metrics reporting.
*   `ProxyManager`: Orchestrates active proxies and enforces naming uniqueness.
*   `VHostProxyManager`: Coordinates multiple virtual host proxies and ACME state.
*   `MeteredHTTPHandler`: Aggregates traffic metrics for HTTP handlers.
*   `PathMatcher`: Performs segment-aware prefix matching for route selection.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Automatic certificate management.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   Internal packages: `acme`, `metrics`, `tunnel`, `wireguard`.

## Subcomponents
*   `proxy.go`: Core proxy implementations and manager logic.
*   `types.go`: Interface definitions and WireGuard-aware connection wrappers.
*   `BUILD.bazel`: Bazel build targets for library and tests.
*   `vhost/`: Virtual host reverse proxy implementation.
*   `proxy_suite_test.go`: Ginkgo test suite initialization.
*   `proxy_test.go`: Integration tests for proxy functionality.