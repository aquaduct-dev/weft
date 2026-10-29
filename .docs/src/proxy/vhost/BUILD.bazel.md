<!-- docdaemon ts:2026-10-29T21:04:44Z hash:0fd8807efac28462 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This Bazel build file defines the Go library and test targets for the virtual host proxying subsystem.

The `vhost` library implements HTTP/HTTPS termination, ACME certificate management, and request routing for multiple virtual hosts. It supports HTTP/3 (QUIC) alongside standard TCP listeners, handling TLS handshakes via `autocert`. The system routes HTTP-01 ACME challenges to sibling nodes in a cluster to ensure validators can reach the node holding the key authorization, avoiding redirect issues with round-robin DNS. It also exposes a `/certificates` endpoint for monitoring cached TLS certificates.

Key dependencies include `quic-go` for HTTP/3 support, `zerolog` for structured logging, and internal packages for ACME logic, utility functions, metrics, and WireGuard integration. The `WGAwareRoundTripper` optimizes transport selection based on target IP ranges.

Tests cover ACME failure scenarios, certificate handling, challenge proxying, path prefix matching, and race conditions using Ginkgo and Gomega.