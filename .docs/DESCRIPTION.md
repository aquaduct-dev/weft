<!-- docdaemon ts:2026-10-15T20:43:38Z hash:b0f643c0a6f8d588 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory serves as the root of the Weft project, defining the build system, CI/CD pipelines, and entry points for the Layer 4/Layer 7 tunnelling proxy.

## Overview
The repository root orchestrates the development lifecycle using Bazel for reproducible builds across Linux, Windows, and macOS. It integrates GitHub Actions to automate testing, multi-architecture container publishing, and release management. The structure separates CLI logic, core networking services, and infrastructure tooling into distinct sub-packages while maintaining a unified build graph.

## Deep Dive
### Build Configuration
`MODULE.bazel` and `BUILD.bazel` define the Go module dependencies and cross-compilation rules. Gazelle manages dependency synchronization, while `go_cross_binary` targets produce platform-specific executables. The configuration isolates toolchain versions to prevent collisions with downstream consumers.

### CI/CD Automation
The `.github/workflows` directory contains `test.yml` for continuous integration and `release.yml` for distribution. Tests run against the entire workspace using Bazelisk, leveraging cache optimization for speed. Releases trigger multi-platform builds, sanity checks, and pushes to the GitHub Container Registry (GHCR).

### Development Tooling
Scripts in `scripts/` enforce code quality and build stability. `setup-pre-commit-hook.sh` ensures BUILD files are synchronized via Gazelle before commits. `workspace_status.sh` provides stable Git metadata to Bazel, enabling effective artifact caching during incremental development.

### Application Entry Points
`main.go` initializes the Cobra-based CLI defined in `cmd/`. This entry point delegates argument parsing and signal handling to the command tree, keeping business logic isolated in the `src/` package. The `container/` directory defines OCI image rules for packaging these binaries.

## Key Interfaces
- `Execute()`: Main entry point for CLI execution in `cmd/root.go`.
- `test.yml`: CI workflow for validation and testing.
- `release.yml`: Release workflow for packaging and distribution.
- `weft_lib`: Core Bazel library target compiling `main.go`.
- `setup-pre-commit-hook.sh`: Script for installing Git pre-commit hooks.
- `workspace_status.sh`: Script for emitting stable build metadata.

## Dependencies
- Bazel and Bazelisk for build management.
- Java 17 (Temurin) for Bazel execution environment.
- GitHub Actions Cache actions for performance optimization.
- Go 1.25.4 and associated rules (rules_go, gazelle).
- rules_oci for container image building.

## Subcomponents
- .github/workflows/test.yml
- .github/workflows/release.yml
- BUILD.bazel
- MODULE.bazel
- README.md
- main.go
- cmd/
- container/
- scripts/
- src/
- test/
- types/
- wireguard/