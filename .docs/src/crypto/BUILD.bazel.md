<!-- docdaemon ts:2026-10-09T01:40:14Z hash:d8a856e052c519b8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `crypto` Go library and its associated test suite.

### Purpose
The `BUILD.bazel` file configures the build system for the `src/crypto` package within the Weft project. It ensures that the Go source code is compiled into a reusable library and that tests can be executed using the Ginkgo and Gomega frameworks.

### Build Targets

#### `go_library`
*   **Name**: `crypto`
*   **Source**: Compiles `crypto.go`.
*   **Import Path**: `github.com/aquaduct-dev/weft/src/crypto`
*   **Visibility**: Public, allowing other packages in the repository to depend on this library.

#### `go_test`
*   **Name**: `crypto_test`
*   **Source**: Runs tests defined in `crypto_test.go`.
*   **Dependencies**:
    *   The local `:crypto` library.
    *   External dependencies for testing: `ginkgo` and `gomega` (via `@com_github_onsi_ginkgo_v2` and `@com_github_onsi_gomega`).