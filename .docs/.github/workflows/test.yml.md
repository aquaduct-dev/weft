<!-- docdaemon ts:2026-10-09T01:40:00Z hash:592c90727795e24c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This GitHub Actions workflow executes the full test suite using Bazel on every push.

### Purpose
The file defines a CI job named `test` that runs on `ubuntu-latest`. It ensures reproducible builds by managing Bazel's remote cache and executing all tests in the repository.

### Workflow Steps
1. **Cache Key Calculation**: Computes the previous run number to optimize cache restoration.
2. **Cache Restoration**: Attempts to restore the Bazel execution cache from the previous run using `actions/cache/restore@v4`.
3. **Repository Checkout**: Clones the repository with full history (`fetch-depth: 0`) to support accurate versioning or tagging if needed.
4. **Environment Setup**: Installs Java 17 (Temurin distribution) as required by Bazel.
5. **Bazelisk Installation**: Downloads and installs `bazelisk` to manage Bazel versions dynamically.
6. **Test Execution**: Runs `bazelisk test //...` to execute all tests in the workspace.
7. **Cache Saving**: Saves the updated Bazel cache for future runs using `actions/cache/save@v4`.

### Integration
This workflow is triggered on every `push` event. It relies on the presence of a `WORKSPACE` or `MODULE.bazel` file and assumes standard Bazel project structure. The cache strategy aims to reduce build times by reusing artifacts from the immediately preceding run.