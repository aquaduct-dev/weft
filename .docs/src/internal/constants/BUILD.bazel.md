<!-- docdaemon ts:2026-10-19T23:25:47Z hash:2c3e519a5befdf34 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the internal constants package.

The `go_library` target builds `constants.go` into a public Go library, making it available to other packages within the repository via its import path `github.com/aquaduct-dev/weft/src/internal/constants`.

The `go_test` target runs tests defined in `constants_test.go`, embedding the main library to ensure the constants are accessible during testing. Recent changes removed unused redaction constants and added validation tests to verify that default subnet and server IP configurations match their string representations and that the server IP resides within the subnet.