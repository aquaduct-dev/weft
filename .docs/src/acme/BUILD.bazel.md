<!-- docdaemon ts:2026-10-29T21:04:44Z hash:e6e6b3452e74980e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the ACME package, which handles certificate acquisition and HTTP-01 challenge proxying.

The `go_library` target compiles `acme.go`, `challenge_proxy.go`, and `testing_helpers.go`. It exposes the package publicly for downstream consumers and depends on `zerolog` for structured logging and `x/crypto/acme/autocert` for core ACME protocol implementation. The library emits events (e.g., `acme_cache_hit`) to track certificate lifecycle stages.

The `go_test` target runs tests using Ginkgo and Gomega. It embeds the main library and includes a live TLS peer test seam to verify peer fallback logic and leader election behavior during challenge resolution. This setup supports the proxy mechanism that forwards HTTP-01 challenges to sibling nodes when round-robin DNS directs validators to non-authoritative servers, avoiding issues with bare IP redirects.