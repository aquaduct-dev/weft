<!-- docdaemon ts:2026-10-09T01:40:11Z hash:26453fcd2b7a76e6 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `auth` Go package and its associated tests.

### Purpose
The `BUILD.bazel` file configures the compilation and testing of the authentication module within the Weft project. It ensures that the `auth` library is publicly accessible to other packages in the repository while correctly linking its dependencies.

### Build Rules

#### `go_library`
- **Name**: `auth`
- **Source**: Compiles `auth.go`.
- **Visibility**: Set to `public`, allowing any package in the repository to import this library.
- **Dependencies**:
  - `//src/version`: Internal dependency for versioning information.
  - `@com_github_golang_jwt_jwt_v4//:jwt`: External dependency for JWT handling.
  - `@com_github_rs_zerolog//log`: External dependency for structured logging.

#### `go_test`
- **Name**: `auth_test`
- **Sources**: Includes `auth_test.go` and `fingerprint_test.go`.
- **Embedding**: Embeds the `:auth` library target to provide access to production code during testing.
- **Dependencies**:
  - `//src/version`: Required for version-related assertions.
  - `@com_github_golang_jwt_jwt_v4//:jwt`: Required for JWT-related test cases.