<!-- docdaemon ts:2026-10-19T23:25:50Z hash:24e4009c4d299bf1 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the `proxy` Go package, including its library sources and associated test suite.

The `go_library` target builds the core proxy logic from `proxy.go` and `types.go`. It exposes the package publicly and depends on internal constants, utilities, virtual host management (`vhost`, `vhost/meter`), WireGuard integration, and logging via Zerolog. The gVisor adapter is included to support network stack operations.

The `go_test` target runs tests using Ginkgo and Gomega. It embeds the main library and adds dependencies for testing the WireGuard netstack implementation. Recent changes addressed a panic in `WGAwareUDPConn.ReadFromUDP` when reading from a closed connection, ensuring proper error handling instead of crashing during session termination.