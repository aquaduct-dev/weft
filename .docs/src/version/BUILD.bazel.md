<!-- docdaemon ts:2026-10-09T01:40:54Z hash:01e0e29698ffa766 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `version` package, which exposes application metadata such as git commit hashes.

### Purpose
The `BUILD.bazel` file configures the Go library and test targets for the `src/version` module. It ensures that version information is injected at compile time via linker flags (`x_defs`), allowing the application to report its build identity without hardcoding values in source files.

### Build Targets

#### `go_library(name = "version")`
Defines the main library target.
- **Sources**: Compiles `version.go`.
- **Import Path**: Sets the canonical import path to `github.com/aquaduct-dev/weft/src/version`.
- **Visibility**: Marked as `public`, allowing any package in the repository to depend on it.
- **Linker Flags**: Uses `x_defs` to inject external variables into the Go binary:
  - `Commit`: Populated with `{STABLE_GIT_COMMIT}`.
  - `CommitDate`: Populated with `{STABLE_GIT_COMMIT_DATE}`.
  These placeholders are resolved by the Bazel build system (typically via `rules_go`'s `go_repository` or custom build rules) to provide accurate versioning data.

#### `go_test(name = "version_test")`
Defines the unit test target.
- **Sources**: Runs tests defined in `version_test.go`.
- **Embedding**: Embeds the `:version` library to ensure tests run against the actual compiled code with injected version info.

### Integration
This package serves as a central point for retrieving build-time metadata. Other parts of the application can import this package to access version details, ensuring consistency across logs, API responses, and CLI outputs.