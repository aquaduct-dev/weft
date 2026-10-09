<!-- docdaemon ts:2026-10-09T01:40:18Z hash:38c3ee0aa3b5d73b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the internal utility package and its associated tests.

### Purpose
The `BUILD.bazel` file configures the Go build system for the `src/internal/util` module. It establishes the compilation unit for the core utility logic and ensures that tests are correctly linked against the implementation.

### Build Targets

*   **`util` (`go_library`)**: Compiles `util.go` into a library target.
    *   **Import Path**: `github.com/aquaduct-dev/weft/src/internal/util`. This path is used by other packages to import this functionality.
    *   **Visibility**: Set to `public`, allowing any package in the repository to depend on this library.
*   **`util_test` (`go_test`)**: Runs the test suite defined in `util_test.go`.
    *   **Embeds**: The test target embeds the `:util` library, ensuring the code under test is available during execution.