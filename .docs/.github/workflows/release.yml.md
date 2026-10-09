<!-- docdaemon ts:2026-10-09T01:40:01Z hash:065810e19d12888b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This workflow automates the multi-platform binary build, container image push, and GitHub release creation for the Weft project following successful test runs on the main branch.

### Purpose
Triggered by the completion of the "Test" workflow, this job orchestrates the end-to-end release process. It ensures that only verified code is packaged into distributable binaries and container images.

### Key Functions
- **Cache Management**: Restores and saves Bazel build caches using run-specific keys to optimize build times across platforms.
- **Multi-Platform Builds**: Compiles Go binaries for Linux (AMD64/ARM64), Windows (AMD64), and macOS (AMD64/ARM64) using Bazelisk and specific toolchain configurations.
- **Artifact Validation**: Performs sanity checks on generated binaries to verify architecture and file format correctness before packaging.
- **Release Creation**: Generates a Git tag (`v1.1.<run_number>`), pushes a multi-arch Docker image to GHCR, and creates a GitHub Release with attached binaries.

### Integration
This workflow depends on the `Test` workflow succeeding. It requires write permissions for `contents` and `packages` to create tags, releases, and push images. Authentication uses the standard `GITHUB_TOKEN` secret.