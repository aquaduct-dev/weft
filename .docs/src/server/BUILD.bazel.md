<!-- docdaemon ts:2026-10-09T01:40:33Z hash:ed8bc5d23c05a81c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `server` Go package and its associated unit tests.

The `go_library` target compiles the core server logic, including HTTP handlers for ACME, authentication, certificates, health checks, metrics, tunnels, and versioning. It also includes supporting modules like the dataplane, janitor, middleware, store, types, and usage reporter. The library depends on internal packages (`acme`, `crypto`, `dns`, `proxy`, `version`) and external libraries for JWT handling, logging, and WireGuard management.

The `go_test` target runs the corresponding test suite by embedding the main library. Tests cover endpoint wiping, handler behaviors, janitor logic, store operations, and usage reporting. Test dependencies mirror the library's core requirements but exclude some broader network-related deps like `acme` and `dns` unless explicitly needed for specific test cases.