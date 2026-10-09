<!-- docdaemon ts:2026-10-09T01:41:02Z hash:c70812393cd41cbb model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rule for the `types` Go package, exposing it for use by other modules in the repository.

### Purpose
The `BUILD.bazel` file configures the `go_library` target named `types`. It compiles `types.go` into a reusable library that can be imported by downstream packages.

### Configuration Details
- **Target Name**: `types`
- **Source**: `types.go`
- **Import Path**: `github.com/aquaduct-dev/weft/types`
- **Visibility**: Public, allowing any package in the workspace to depend on this library via `//types`.