<!-- docdaemon ts:2026-10-09T01:40:55Z hash:307489ffb1427abf model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the shell-based test suite and shared library utilities.

It configures `sh_library` to provide common testing infrastructure via `lib.sh`, including runtime dependencies like the `weft` binary. The bulk of the file declares individual `sh_test` targets, each mapping a specific shell script to its execution environment.

Tests are categorized by functionality:
- **Protocol Tunnels**: TCP, HTTP, HTTPS, and UDP tunneling logic.
- **Proxy Modes**: TCP, HTTP, and UDP proxy implementations.
- **Feature Tests**: Path rewriting, header modifiers, redirects, matchers, and retries.
- **Billing & Reporting**: Metrics collection, multi-tunnel reporting, and interrupt handling.
- **Security & Health**: MITM support, secret enforcement, probes, and graceful shutdown.

Most tests depend on `:lib` for shared helpers. Some tests (e.g., `test_tcp_tunnel`, `test_http_proxy`) inject the `PROTO` environment variable to parameterize behavior.