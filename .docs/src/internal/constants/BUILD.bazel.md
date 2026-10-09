<!-- docdaemon ts:2026-10-09T01:40:15Z hash:d3694b5d2f81c429 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rule for the internal constants Go package.

It configures the `go_library` target named `constants`, which compiles `constants.go`. The package is exposed publicly to allow other modules within the repository to import it via `github.com/aquaduct-dev/weft/src/internal/constants`.