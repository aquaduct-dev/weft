<!-- docdaemon ts:2026-10-09T01:39:59Z hash:39dae1c486faa224 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel `go_library` target for the Weft command-line interface package.

It aggregates the core CLI source files (`list`, `probe`, `proxy`, `root`, `server`, `tunnel`) into a single library target named `cmd`. The target exposes itself publicly to allow other packages to depend on the CLI implementation.

The library depends on internal application modules including authentication, client logic, logging, proxying (including vhost support), server handling, and tunnel management. It also relies on external dependencies for structured logging via `zerolog`, command-line parsing via `cobra`, and network interface manipulation via `netlink`.