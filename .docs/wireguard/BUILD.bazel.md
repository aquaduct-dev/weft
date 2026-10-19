<!-- docdaemon ts:2026-10-19T23:26:02Z hash:09ba2da813db3127 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `wireguard` Go package and its associated tests.

The `go_library` target named `wireguard` compiles `wireguard.go` into a library with public visibility, making it accessible to other packages in the repository. It imports dependencies from the `zx2c4/golang-wireguard` ecosystem, specifically targeting the `conn`, `device`, `tun`, and `tun/netstack` subpackages, as well as `wgtypes` from `wgctrl`. This structure supports the integration of WireGuard networking capabilities within the `weft` project.

The `go_test` target named `wireguard_test` builds and runs unit tests found in `wireguard_test.go`. It embeds the main library via the `embed` attribute to access internal state or helpers during testing and depends on `wgtypes` for type definitions. The test suite includes table-driven tests for configuration serialization (`ConfigToString`) and verifies the behavior of the `Verbose` flag, ensuring accurate UAPI text representation for various peer states.