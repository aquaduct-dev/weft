<!-- docdaemon ts:2026-10-09T01:40:50Z hash:76750c0632be7f24 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `tunnel` Go library.

It configures the `go_library` target named `tunnel`, specifying `tunnel.go` as the source and setting the import path to `github.com/aquaduct-dev/weft/src/tunnel`. The library is marked public, allowing other packages in the repository to depend on it.

The build depends on several internal and external packages:
- **Internal dependencies**: `//src/internal/util`, `//src/proxy`, `//types`, and `//wireguard`. These suggest the tunnel implementation interacts with utility functions, proxy logic, type definitions, and WireGuard-specific functionality.
- **External dependencies**: `@com_github_rs_zerolog//log` for structured logging and `@com_zx2c4_golang_wireguard_wgctrl//wgtypes` for WireGuard type handling.

This configuration ensures that the `tunnel` package is correctly compiled and linked within the larger Weft project structure, facilitating modular development and dependency management via Bazel.