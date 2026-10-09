<!-- docdaemon ts:2026-10-09T01:40:00Z hash:5bb0e35386a08d88 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for compiling the Weft Go application across multiple operating systems and architectures.

It configures Gazelle to manage dependencies and sets `github.com/aquaduct-dev/weft` as the module prefix. The core logic is encapsulated in `weft_lib`, which compiles `main.go` into a library target. This library is embedded by `weft_raw`, serving as the base binary for cross-compilation.

Five `go_cross_binary` targets produce platform-specific executables:
- `weft`: Linux AMD64 (default)
- `weft_arm64`: Linux ARM64
- `weft_windows_amd64`: Windows AMD64
- `weft_darwin_amd64`: macOS Intel
- `weft_darwin_arm64`: macOS Apple Silicon

All binaries are publicly visible, allowing downstream packages to depend on them. A `gazelle_test` rule ensures the BUILD file remains synchronized with the source code structure.