<!-- docdaemon ts:2026-11-01T18:05:29Z hash:21b191515649ee5a model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the ACME package, which manages TLS certificate acquisition and HTTP-01 challenge handling in a round-robin DNS environment.

The `go_library` target compiles the core ACME logic, including `challenge_proxy.go` and `http01_only.go`. The `http01_only.go` implementation restricts validation to HTTP-01 challenges to prevent `tls-alpn-01` failures caused by round-robin DNS resolution hitting nodes that do not hold the current authorization key. The `challenge_proxy.go` module proxies HTTP-01 challenges to sibling nodes rather than issuing redirects, ensuring Let's Encrypt validators can complete authentication regardless of which node they contact.

Dependencies include `zerolog` for structured event logging (e.g., `acme_cache_hit`, `acme_issuance_started`) and `golang.org/x/crypto/acme` for protocol interaction.

The `go_test` target runs the test suite using Ginkgo and Gomega. It embeds the library and includes tests for peer fallback mechanisms and leader election, verifying that the system correctly skips dead peers and handles registration loops when multiple bastion nodes are present.