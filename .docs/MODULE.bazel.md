<!-- docdaemon ts:2026-10-09T01:40:03Z hash:2a9b078aabe78ace model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel module configuration, external dependencies, and container image rules for the `aquaduct_weft` project.

### Purpose
`MODULE.bazel` serves as the root manifest for Bazel’s bzlmod system. It declares the module name (`aquaduct_weft`) and version, then registers all necessary toolchains and third-party repositories required to build Go binaries and OCI containers without a legacy `WORKSPACE` file.

### Key Components

**External Dependencies**
The file imports several critical Bazel rules via `bazel_dep`:
*   **Build Rules**: `rules_go`, `gazelle`, `rules_pkg`, `rules_shell`, and `tar.bzl`.
*   **Containerization**: `rules_oci` enables building multi-architecture container images.

**Go SDK Configuration**
It configures the Go toolchain using `use_extension` from `@rules_go`. The SDK is pinned to version `1.25.4` and sourced from the local `go.mod` file. The resulting `go_sdk` repository is registered as a toolchain.

**Go Dependencies**
Using Gazelle’s extension, direct Go dependencies are resolved from `//:go.mod`. These are explicitly listed in `use_repo` to ensure reproducible builds. The list includes libraries for JWT handling, logging (zerolog), CLI parsing (cobra), testing (ginkgo/gomega), networking (quic-go, netlink), and WireGuard integration.

**OCI Base Images**
The `rules_oci` extension pulls a multi-architecture Alpine Linux base image. It supports both `linux/amd64` and `linux/arm64/v8` platforms, ensuring the final container can run on diverse hardware architectures.