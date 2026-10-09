<!-- docdaemon ts:2026-10-09T01:40:20Z hash:f5f627b0e560c46f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This Bazel build file defines the Go library and test targets for the `proxy` package.

The `go_library` target compiles `proxy.go` and `types.go` into a library named `proxy`. It exposes the package publicly, allowing other modules to depend on it via its import path `github.com/aquaduct-dev/weft/src/proxy`. The library relies on internal constants and utilities, sub-packages for virtual host handling and metering, WireGuard integration, and external dependencies for logging (`zerolog`) and TCP/IP adapter functionality (`gonet`).

The `go_test` target builds the test suite using Ginkgo and Gomega. It embeds the main library code and depends on the testing frameworks to execute `proxy_suite_test.go` and `proxy_test.go`.