<!-- docdaemon ts:2026-10-09T01:41:28Z hash:66e3d2c4b8dedb72 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory provides internal utilities for URL manipulation, port parsing, and transient failure tracking to stabilize tunnel connections.

## Overview
The `src/internal/util` package offers low-level helpers essential for network proxy operations. It ensures robust handling of URL structures and implements a sliding window counter to prevent premature tunnel teardowns during brief upstream outages. These tools are shared across the codebase to maintain consistency in connection management.

## Deep Dive
### Failure Tracking
`FailureTracker` mitigates transient upstream errors using a sliding window algorithm. It records failure timestamps and only returns true when failures exceed a threshold within a specific time window. This prevents single-client attempts from tearing down tunnels during restarts. The tracker resets automatically upon tripping or manually via `Reset()` after success.

### URL and Port Utilities
`EnsurePort` validates URLs by injecting standard defaults (80/443) for HTTP/HTTPS, rejecting ambiguous schemes like TCP/UDP. `ParsePort` extracts integer ports from host strings with strict format validation. `RewriteHost` updates hostnames while preserving existing ports, safely handling empty or wildcard addresses.

## Key Interfaces
- `type FailureTracker struct`: Sliding window counter for upstream dial failures.
- `func EnsurePort(url *url.URL) error`: Validates and injects default ports into URLs.
- `func ParsePort(host string, defaultPort int) (int, error)`: Extracts port from host string.
- `func RewriteHost(url *url.URL, newHost string)`: Updates URL hostname while keeping the port.

## Dependencies
- Standard library `net/url`
- Standard library `time`

## Subcomponents
- `util.go`: Core implementation of utility functions and failure tracking.
- `util_test.go`: Unit tests for failure tracker logic and reset behavior.
- `BUILD.bazel`: Bazel build configuration for the Go library and tests.