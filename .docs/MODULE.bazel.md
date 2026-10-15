<!-- docdaemon ts:2026-10-15T20:41:53Z hash:d30167a4f2b1aaf4 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel module configuration for `aquaduct_weft`, declaring external dependencies and configuring Go and OCI toolchains.

### Purpose
`MODULE.bazel` serves as the root manifest for the Bazel module system (bzlmod). It declares the module name, version, and all direct dependencies required to build the project without a legacy `WORKSPACE` file.

### Dependencies
The file imports several rules via `bazel_dep`:
- **rules_oci**: Enables container image building and pulling.
- **rules_go & gazelle**: Provides the Go build system and dependency management.
- **rules_pkg & rules_shell**: Supports packaging and shell script execution.
- **tar.bzl**: Assists with tar archive operations.

### Toolchain Configuration
Go and base images are marked as `dev_dependency`. This isolates their repository names (`go_sdk`, `alpine`) from consuming modules, allowing downstream projects like `weft-operator` to use their own versions without collision.

1.  **Go SDK**: Configured via `@rules_go//go:extensions.bzl` using `//:go.mod` and downloading version `1.25.4`.
2.  **Go Dependencies**: Managed by Gazelle's extension. Direct dependencies are explicitly listed in `use_repo` to ensure reproducible builds.
3.  **OCI Base Image**: Pulls Alpine Linux (`sha256:...`) for both `linux/amd64` and `linux/arm64/v8` platforms.