<!-- docdaemon ts:2026-10-30T02:43:08Z hash:eb1949f714e7a9f6 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the `vhost` package, which manages virtual hosting, TLS certificate issuance, and HTTP/3 termination.

The `go_library` target compiles `challenge_proxy.go`, `errorlog.go`, and `vhost.go`. It exposes the `VHostProxyManager` type to other packages, enabling dynamic route registration and ACME-based certificate management. The library depends on internal utilities, the `meter` sub-package for metrics, and external dependencies like `quic-go` for HTTP/3 support and `autocert` for Let's Encrypt integration.

The `go_test` target runs the test suite using Ginkgo and Gomega. It embeds the main library and includes tests for ACME failure handling, certificate lifecycle, challenge proxying (including sibling node redirection), path prefix matching, and HTTP/3 Alt-Svc header behavior. These tests ensure robustness against race conditions and network failures during tunnel establishment.