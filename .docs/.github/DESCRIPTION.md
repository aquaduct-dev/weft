<!-- docdaemon ts:2026-10-09T01:48:02Z hash:1595de2184460a99 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory defines the CI/CD pipeline for the Weft project, handling continuous integration testing and automated multi-platform releases.

## Overview
The `.github/workflows` directory orchestrates the build, test, and distribution lifecycle using GitHub Actions. It ensures code quality through comprehensive Bazel-based testing and automates the creation of binaries and container images. The system supports reproducible builds across Linux, Windows, and macOS environments, leveraging Bazelisk for dependency management.

## Deep Dive
### Test Workflow (`test.yml`)
Executed on every push, this workflow validates code integrity using Bazel. It installs Java 17 (Temurin) and Bazelisk to manage dependencies dynamically. A key feature is its cache optimization strategy, which restores execution caches from previous runs to accelerate build times. Tests are run against the entire workspace (`//...`) to ensure no regressions occur.

### Release Workflow (`release.yml`)
Triggered by a successful test run, this workflow handles packaging and distribution. It orchestrates multi-platform builds for Linux (AMD64/ARM64), Windows (AMD64), and macOS (AMD64/ARM64). After generating artifacts, it performs sanity checks to verify binary architecture and format correctness. Finally, it creates a Git tag, pushes a multi-arch Docker image to GHCR, and publishes a GitHub Release with attached binaries.

## Key Interfaces
- `test.yml`: Entry point for CI validation jobs.
- `release.yml`: Entry point for release automation jobs.
- `GITHUB_TOKEN`: Standard secret used for authentication in both workflows.

## Dependencies
- Bazel and Bazelisk for build management.
- Java 17 (Temurin) for Bazel execution environment.
- GitHub Actions Cache actions for performance optimization.
- Write permissions for `contents` and `packages`.

## Subcomponents
- `release.yml`
- `test.yml`