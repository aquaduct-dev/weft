<!-- docdaemon ts:2026-10-09T01:48:02Z hash:0efe25175a4d252a model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory contains automation scripts for Git hook installation and Bazel build optimization.

## Overview
The `scripts` directory provides essential tooling to streamline the development workflow within a Bazel-based project. It ensures code quality through automated pre-commit checks and optimizes build performance by stabilizing version metadata. These utilities reduce manual overhead and enforce consistency across the repository.

## Deep Dive
### Pre-Commit Enforcement
The `setup-pre-commit-hook.sh` script automates the configuration of Git hooks. It installs a pre-commit handler that mandates two critical checks: synchronizing BUILD files via Gazelle and passing the full test suite. This prevents drift between source code and build rules, ensuring that no commit introduces broken dependencies or failing tests. Developers must run this script once after cloning the repository to activate these safeguards.

### Build Stability
The `workspace_status.sh` script generates stable environment variables for Bazel’s `x_defs`. By exposing the short Git commit hash and committer date as `STABLE_GIT_COMMIT` and `STABLE_GIT_COMMIT_DATE`, it allows the build system to cache artifacts effectively. Re-linking only occurs when these values change, significantly speeding up incremental builds during active development where source changes do not alter Git history.

## Key Interfaces
- `setup-pre-commit-hook.sh`: Entry point for installing and configuring the Git pre-commit hook.
- `workspace_status.sh`: Script interface for emitting stable Git metadata to Bazel.

## Dependencies
- Git (for repository management and metadata extraction)
- Bazel (for build execution and dependency management)
- Gazelle (for automatic BUILD file generation)

## Subcomponents
- setup-pre-commit-hook.sh
- workspace_status.sh