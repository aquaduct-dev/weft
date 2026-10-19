<!-- docdaemon ts:2026-10-19T23:26:04Z hash:8fc8193a75526510 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the ACME package, which handles certificate acquisition and peer-to-peer challenge redirection.

The `go_library` target compiles `acme.go`, `acme_redirect.go`, and `testing_helpers.go`. It exposes the package publicly and depends on `zerolog` for structured logging and `autocert` for TLS certificate management. Recent changes introduced event logging for certificate lifecycle auditing (cache hits, issuance start/success/failure) and logic for redirecting challenges to peers based on leader election and peer availability.

The `go_test` target runs tests using Ginkgo and Gomega, embedding the library under test. It verifies behaviors such as skipping dead higher peers during registration and declaring leadership when no higher peer responds. The test suite uses specific network seams (e.g., 127.0.0.3 for live peers, 127.0.0.4 for dead ones) to validate these fallback mechanisms.