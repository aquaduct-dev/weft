<!-- docdaemon ts:2026-10-19T23:25:51Z hash:ff8512b4ca70c359 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the `vhost` package, which manages virtual hosts, TLS certificates, and HTTP/3 termination.

The `go_library` target compiles `acme_redirect.go`, `errorlog.go`, and `vhost.go`. It exposes the package publicly to allow other modules to depend on virtual host management logic. Key dependencies include `quic-go` for HTTP/3 support, `autocert` for ACME certificate issuance, and internal utilities for logging and metering.

The `go_test` target runs the test suite using Ginkgo and Gomega. It embeds the main library and adds testing-specific dependencies like `src/crypto`. The tests cover ACME failure handling, certificate management, path prefix matching, and race conditions in concurrent access to TLS configurations and ACME hosts.