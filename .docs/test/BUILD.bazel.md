<!-- docdaemon ts:2026-10-15T20:41:50Z hash:46a692fae609866d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the shell-based test suite and shared library.

It configures `sh_library` to provide common utilities via `lib.sh` and the `//:weft` data dependency. It then declares a series of `sh_test` targets, each executing specific shell scripts to verify tunneling, proxying, routing, and billing logic. Tests are parameterized using the `PROTO` environment variable (tcp, http, https, udp) where applicable. The `test_https_tunnel` target explicitly includes `test_tcp_tunnel.sh` in its data dependencies, likely for shared helper functions or fixtures. All tests depend on the `:lib` target for shared code.