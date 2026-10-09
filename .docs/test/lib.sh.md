<!-- docdaemon ts:2026-10-09T01:40:54Z hash:03f81d804842253f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a shared library of Bash helper functions to bootstrap, manage, and clean up test environments for the `weft` application.

It locates the `weft` binary using Bazel runfiles or local paths, then offers utilities to find free ports and wait for network availability (TCP/UDP). The core value lies in its integration helpers: it spins up mock HTTP reporting servers to capture usage data, launches the `weft` server with generated secrets, starts target HTTP servers, and manages `weft` tunnels. All background processes are tracked in a global `pids` array for cleanup via a trap handler that preserves logs on failure if `VERBOSE` is set.