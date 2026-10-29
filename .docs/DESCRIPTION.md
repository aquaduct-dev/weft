<!-- docdaemon ts:2026-10-29T21:07:37Z hash:632b1aea95ae7c29 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory serves as the root of the Weft project, defining the build system, CI/CD pipelines, and entry points for the Go-based tunnelling proxy.

## Overview
The repository root orchestrates the development lifecycle using Bazel for reproducible builds across Linux, Windows, and macOS. It integrates GitHub Actions to automate testing, multi-architecture container image publishing, and binary distribution. The structure separates CLI logic, core server infrastructure, and networking abstractions into dedicated sub-packages while maintaining a unified module configuration.

## Deep Dive
### Build Configuration
`MODULE.bazel` and `BUILD.bazel` define the Bazel module manifest and compilation rules. Gazelle manages dependency synchronization, while `go_cross_binary` targets produce platform-specific executables. The `container/` directory extends this by packaging binaries into multi-arch OCI images using `rules_oci`, ensuring consistent deployment via `ghcr.io/aquaduct-dev/weft`.

### CI/CD Automation
The `.github/workflows/` directory contains `test.yml` and `release.yml`. The test workflow validates code integrity using Bazel’s execution cache optimization. The release workflow triggers on successful tests, building binaries for all supported platforms, verifying artifact integrity, and publishing Docker images with the `latest` tag.

### Development Tooling
`scripts/` provides automation for developer workflows. `setup-pre-commit-hook.sh` enforces Gazelle synchronization and test passing before commits. `workspace_status.sh` stabilizes Git metadata for Bazel’s `x_defs`, enabling efficient incremental builds by preventing unnecessary re-linking when only source code changes.

## Key Interfaces
- `main.go`: Application entry point delegating to `cmd.Execute()`.
- `weft_lib`: Core library target compiling `main.go` for cross-compilation.
- `weft_image`: Multi-architecture OCI index published to GHCR.
- `GITHUB_TOKEN`: Secret used for authentication in CI/CD workflows.

## Dependencies
- Bazel and Bazelisk for build management.
- Java 17 (Temurin) for Bazel execution environment.
- GitHub Actions Cache actions for performance optimization.
- `rules_oci`, `rules_go`, `gazelle` for container and Go tooling.

## Subcomponents
- `.github/workflows/test.yml`
- `.github/workflows/release.yml`
- `BUILD.bazel`
- `MODULE.bazel`
- `README.md`
- `cmd/`
- `container/`
- `main.go`
- `scripts/`
- `src/`
- `test/`
- `types/`
- `wireguard/`