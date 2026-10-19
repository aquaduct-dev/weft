<!-- docdaemon ts:2026-10-19T23:25:49Z hash:f315991d12794c95 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the `logging` Go package and its associated tests.

The `go_library` target builds the core logging implementation from `logging.go`. It exposes the package publicly to allow other modules in the repository to import it via `github.com/aquaduct-dev/weft/src/logging`. The library depends on the `zerolog` and `log` packages from the external `com_github_rs_zerolog` repository, which provide the underlying structured logging capabilities.

The `go_test` target runs unit tests defined in `logging_test.go`. It embeds the main library to ensure test coverage of the public API. Like the library, the test target depends on `zerolog` and `log` to facilitate testing against the actual logging implementations.

Recent changes to this file reflect a tightening of documentation and test coverage for the `Init` function, specifically ensuring that both development (console output) and production (JSON logger) environments are correctly tested under different `WEFT_ENV` settings.