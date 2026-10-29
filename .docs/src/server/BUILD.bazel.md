<!-- docdaemon ts:2026-10-29T21:04:49Z hash:fc9221386970f30f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the Weft server package, bundling core logic and tests.

The `go_library` target compiles the main server implementation, including HTTP handlers for authentication, certificates, health checks, metrics, tunnels, and versioning. It integrates with internal packages for crypto, DNS, proxying, and WireGuard management, while exposing itself publicly for downstream consumption.

The `go_test` target aggregates unit tests for all server components, embedding the library to access internal state and helpers. It shares most dependencies with the library but excludes external logging libraries to keep test binaries lightweight.

Key architectural decisions reflected in this structure include:
- **Modular Handlers**: Separate source files (`handlers_*.go`) isolate distinct API responsibilities, making it easy to add new endpoints like `/certificates` or modify auth flows without touching core server logic.
- **Security Hardening**: The inclusion of `middleware.go` and specific handler tests reflects ongoing security fixes, such as constant-time comparisons for secrets and JWT subject validation to prevent tunnel hijacking.
- **Dataplane Integrity**: Tests like `dataplane_endpoint_wipe_test.go` ensure that WireGuard configuration updates correctly wipe stale peer endpoints, maintaining network isolation during roams or removals.