<!-- docdaemon ts:2026-10-09T01:41:54Z hash:da745e4a8a722ed8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory contains GitHub Actions workflows for continuous integration testing and automated multi-platform releases.

## Overview
The `.github/workflows` directory defines the CI/CD pipeline for the Weft project. It ensures code quality through comprehensive testing and automates the distribution of binaries and container images via GitHub Releases. The system relies on Bazel for reproducible builds across multiple operating systems and architectures.

## Deep Dive
### Test Workflow (`test.yml`)
Executed on every push, this workflow validates code integrity using Bazel. It installs Java 17 and Bazelisk to manage dependencies dynamically. A key feature is its cache optimization strategy, which restores execution caches from previous runs to accelerate build times. Tests are run against the entire workspace (`//...`) to ensure no regressions occur.

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