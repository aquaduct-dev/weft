<!-- docdaemon ts:2026-10-19T23:25:44Z hash:3a6b0aaf2aeb8776 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the DNS provider library, specifically configuring the Go library and its associated tests.

### Build Configuration
The `go_library` target named `dns` compiles `cloudflare.go` into a public package at `github.com/aquaduct-dev/weft/src/dns`. It depends on the Cloudflare Go SDK (`@com_github_cloudflare_cloudflare_go`) and the Zerolog logging library (`@com_github_rs_zerolog`).

### Testing
The `go_test` target `dns_test` runs tests from `cloudflare_test.go`, embedding the main library code. It also links against the Cloudflare SDK to facilitate integration or unit testing of DNS operations.

### Contextual Notes
Recent updates to this module addressed zone matching logic in `UpdateRecord`. The previous implementation used a simple suffix check that incorrectly matched subdomains (e.g., `notexample.com` against `example.com`). The current codebase implements `findZone`, which enforces exact matches or strict label-boundary suffixes (prefixed with `.`), ignoring case and trailing dots. This ensures precise zone selection during record updates.