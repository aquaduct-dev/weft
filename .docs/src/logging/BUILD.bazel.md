<!-- docdaemon ts:2026-10-09T01:40:19Z hash:8757c2f08394a55f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `logging` Go package.

It configures a `go_library` target named `logging`, exposing it publicly for consumption by other packages within the repository. The library compiles `src/logging/logging.go` and declares a dependency on the `zerolog` logging library via external dependencies. This setup ensures that any module importing `github.com/aquaduct-dev/weft/src/logging` can access the logging utilities provided by this package, leveraging `zerolog` for high-performance structured logging capabilities.