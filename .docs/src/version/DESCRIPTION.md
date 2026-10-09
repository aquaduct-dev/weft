<!-- docdaemon ts:2026-10-09T01:41:55Z hash:4146ef70296a7e8a model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `version` package exposes application build metadata, such as git commit hashes and dates, injected at compile time.

## Overview
This directory provides a centralized mechanism for reporting the identity of the running binary. By leveraging Bazel’s linker flags, it ensures that version information is accurate without hardcoding values in source files. This consistency supports reliable logging, health checks, and API responses across the application.

## Deep Dive
### Build-Time Injection
The core functionality relies on Bazel’s `x_defs` to inject variables into the Go binary during the link phase. The `BUILD.bazel` file configures the `go_library` target to map external placeholders like `{STABLE_GIT_COMMIT}` to internal Go variables. This approach decouples build identity from source code, allowing dynamic updates based on the repository state at build time.

### Default Fallbacks
To handle scenarios where stamping is not available, such as local development builds or non-Bazel environments, the package defines default values. If the linker does not provide specific commit data, the `Commit` and `CommitDate` variables retain their "unknown" defaults. This prevents empty strings from appearing in user-facing outputs, ensuring coherent error messages and logs even in un-stamped builds.

### Testing Integrity
Unit tests verify that these default values are always present and non-empty. The `TestDefaultsArePresent` function asserts that both `Commit` and `CommitDate` contain valid strings, safeguarding against runtime issues caused by null version data. This validation ensures that any component relying on this package receives meaningful metadata regardless of the build context.

## Key Interfaces
- `Commit`: Global string variable storing the git commit hash.
- `CommitDate`: Global string variable storing the commit date.

## Dependencies
- Bazel build system (specifically `rules_go`)
- `scripts/workspace_status.sh` (for stamping logic)

## Subcomponents
- `BUILD.bazel`: Defines Go library and test targets with linker flag configurations.
- `version.go`: Declares global version variables with default fallbacks.
- `version_test.go`: Validates that version fields are never empty.