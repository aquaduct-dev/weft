<!-- docdaemon ts:2026-10-09T01:40:13Z hash:9e396dcf27e8aa05 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `client` Go package and its associated unit tests.

## Purpose
The `BUILD.bazel` file configures the compilation and testing of the client-side logic within the Weft project. It establishes the dependencies required to build the client library and run its test suite, ensuring proper isolation and reproducibility via Bazel's dependency graph.

## Build Rules

### go_library
The primary target, `client`, compiles the source files `client.go` and `health_monitor.go`.
- **Import Path**: Set to `github.com/aquaduct-dev/weft/src/client` to match the module structure.
- **Visibility**: Marked as `public`, allowing other packages in the repository to depend on this library.
- **Dependencies**:
  - `//src/auth`: Provides authentication utilities.
  - `//types`: Shares common type definitions.
  - `@com_github_rs_zerolog//log`: Integrates the Zerolog logging library.

### go_test
The `client_test` target executes unit tests defined in `client_test.go`.
- **Dependencies**:
  - `:client`: Links against the main library under test.
  - `//src/auth`: Required for any auth-related mocking or verification in tests.
  - `@com_github_golang_jwt_jwt_v4//:jwt`: Used for JWT handling assertions.
  - `@com_github_stretchr_testify//assert`: Provides assertion helpers for test validation.