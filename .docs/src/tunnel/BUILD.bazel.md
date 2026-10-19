<!-- docdaemon ts:2026-10-19T23:25:59Z hash:2209a222998c3312 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the `tunnel` Go package, exposing the library and its tests to the rest of the repository.

The `go_library` target builds the core tunneling logic from `tunnel.go`. It is marked public, allowing other packages to depend on it. The library relies on internal utilities (`//src/internal/util`), proxy logic (`//src/proxy`), shared types (`//types`), and WireGuard integration (`//wireguard`). It also imports external dependencies for structured logging via `zerolog` and WireGuard configuration management via `wgctrl`.

The `go_test` target compiles `tunnel_test.go`, embedding the main library to facilitate unit testing. Recent changes to this module focused on refining IP resolution logic, specifically ensuring that server endpoints are correctly resolved rather than relying on stale placeholder values like loopback addresses.