<!-- docdaemon ts:2026-10-30T02:45:06Z hash:17364697fe0c65ee model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The repository root defines the build system, CI/CD pipelines, and entry points for the Weft tunnelling proxy application.

## Overview
This directory serves as the project hub, orchestrating the compilation of Go binaries across multiple platforms using Bazel and automating their distribution via GitHub Actions. It integrates containerization rules to produce multi-architecture OCI images and provides scripts to enforce code quality through pre-commit hooks and stable build metadata. The structure separates the CLI entry point from core business logic, ensuring a clean bootstrap process for the application.

## Deep Dive
### Build Configuration
`BUILD.bazel` and `MODULE.bazel` define the Bazel module system, declaring dependencies like `rules_oci` and `gazelle`. The build targets five platform-specific binaries (`weft`, `weft_arm64`, etc.) using `go_cross_binary`, enabling reproducible cross-compilation. A `gazelle_test` rule ensures BUILD files remain synchronized with source code changes, preventing dependency drift.

### CI/CD Automation
The `.github/workflows` directory contains `test.yml` and `release.yml`. The test workflow validates code integrity using Bazel’s full workspace tests, leveraging cache optimization for speed. The release workflow triggers on successful tests, packaging binaries for Linux, Windows, and macOS, verifying binary architectures, and publishing multi-arch Docker images to GHCR alongside Git tags.

### Container Packaging
The `container/` directory uses `pkg_tar` and `oci_image_index` to bundle platform-specific binaries into a unified manifest list. This allows consumers to pull a single image reference that automatically resolves to the correct AMD64 or ARM64 variant based on the host architecture, simplifying deployment pipelines.

### Development Tooling
Scripts in `scripts/` streamline local development. `setup-pre-commit-hook.sh` enforces Gazelle synchronization and test suite execution before commits. `workspace_status.sh` emits stable Git commit hashes to Bazel’s `x_defs`, optimizing incremental builds by avoiding unnecessary re-linking when only source code changes.

## Key Interfaces
- `main()`: Application entry point delegating to the CLI framework.
- `rootCmd`: Base Cobra command defining global flags and execution logic.
- `weft_image`: Multi-architecture OCI image index published to GHCR.
- `GITHUB_TOKEN`: Secret used for authentication in CI/CD workflows.

## Dependencies
- Bazel and Bazelisk for build management.
- Go 1.25+ for application compilation.
- GitHub Actions Cache for performance optimization.
- Cobra and Zerolog for CLI implementation.

## Subcomponents
- `.github/workflows/test.yml`
- `.github/workflows/release.yml`
- `BUILD.bazel`
- `MODULE.bazel`
- `README.md`
- `cmd/`
- `container/`
- `main.go`
- `scripts/setup-pre-commit-hook.sh`
- `scripts/workspace_status.sh`