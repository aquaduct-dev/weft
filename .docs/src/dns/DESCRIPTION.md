<!-- docdaemon ts:2026-10-19T23:27:10Z hash:75bae7ca00637835 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements Cloudflare DNS record synchronization with robust zone resolution logic.

## Overview
The `dns` package provides a library for managing DNS records within the Cloudflare ecosystem. It handles the lifecycle of DNS entries by removing existing records and creating new A and TXT records for a specified hostname. The module ensures precise zone selection to prevent accidental modifications to unrelated domains.

## Deep Dive
### Zone Resolution
The core challenge in this module is identifying the correct Cloudflare zone for a given hostname. Previous implementations used simple suffix matching, which incorrectly associated subdomains like `notexample.com` with the `example.com` zone. The current `findZone` function enforces strict label-boundary matching. It requires an exact match or a suffix prefixed with a dot (e.g., `.example.com`), ensuring case-insensitivity and handling trailing dots correctly. This prevents cross-zone pollution during updates.

### Record Synchronization
The primary operation, `UpdateRecord`, synchronizes DNS state for a specific hostname. It first cleans up all pre-existing records associated with that hostname, regardless of type, to ensure a clean slate. It then creates a new A record pointing to a target IP with a short TTL of 120 seconds and proxy disabled. Finally, it adds a TXT record containing a timestamped update message for auditability. This approach guarantees idempotency and consistency in DNS state.

## Key Interfaces
- `UpdateRecord(hostname, targetIP string, token string) error`: Synchronizes DNS records for a hostname using the provided API token.
- `findZone(hostname string, zones []cloudflare.Zone) string`: Resolves the correct zone ID based on strict label-boundary matching.

## Dependencies
- `github.com/cloudflare/cloudflare-go`: Official Cloudflare Go SDK for API interactions.
- `github.com/rs/zerolog`: Structured logging library.

## Subcomponents
- `cloudflare.go`: Core implementation of DNS record updates and zone resolution.
- `cloudflare_test.go`: Unit tests for zone resolution logic.
- `BUILD.bazel`: Bazel build configuration for the Go library and tests.