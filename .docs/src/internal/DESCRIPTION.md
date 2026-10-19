<!-- docdaemon ts:2026-10-19T23:27:09Z hash:ecdaf347ba7410fd model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory provides immutable network configuration constants and low-level utilities for URL manipulation, port parsing, and transient failure tracking to stabilize tunnel connections.

## Overview
The `src/internal` package serves as the foundational layer for the application’s internal networking logic. It centralizes default WireGuard configuration values to ensure consistency and early validation of static settings. Additionally, it offers shared utility functions that handle robust URL processing and mitigate premature tunnel teardowns during upstream instability. These components are critical for maintaining reliable proxy operations across both HTTP and TCP paths.

## Deep Dive
### Network Defaults
The `constants` package defines immutable defaults for the WireGuard interface, specifically the subnet (`10.1.0.0/16`) and server IP (`10.1.0.1`). By pre-parsing these values into `netip` types at load time, the system ensures immediate panic on malformed data rather than silent runtime failures. This design guarantees logical integrity between string representations and programmatic IP comparisons. Redundant constants, such as redacted private keys, have been removed to clarify scope and reduce maintenance overhead.

### Failure Tracking
To prevent single-client attempts or brief upstream outages from tearing down legitimate tunnels, the `util` package implements a `FailureTracker`. This sliding window counter records failure timestamps and only triggers cleanup when failures exceed a threshold within a specific time window. The tracker resets automatically upon success or manually via `Reset()`, stabilizing connections during restarts or temporary network glitches.

### URL and Port Utilities
The `util` package also includes helpers for URL normalization. `EnsurePort` injects standard defaults (80/443) for HTTP/HTTPS URLs while rejecting ambiguous schemes. `ParsePort` extracts integer ports with strict validation, and `RewriteHost` updates hostnames while preserving existing ports. These tools ensure consistent URL structures across proxy operations.

## Key Interfaces
*   `DefaultSubnetString`: CIDR notation for the default WireGuard subnet.
*   `DefaultServerIPString`: Specific IP address assigned to the server.
*   `DefaultSubnet`: Pre-parsed `netip.Prefix` for programmatic subnet checks.
*   `DefaultServerIP`: Pre-parsed `netip.Addr` for direct IP comparisons.
*   `type FailureTracker struct`: Sliding window counter for upstream dial failures.
*   `func EnsurePort(url *url.URL) error`: Validates and injects default ports into URLs.
*   `func ParsePort(host string, defaultPort int) (int, error)`: Extracts port from host string.
*   `func RewriteHost(url *url.URL, newHost string)`: Updates URL hostname while keeping the port.

## Dependencies
*   Standard library `net/netip`
*   Standard library `net/url`
*   Standard library `time`

## Subcomponents
*   `constants/`: Immutable network configuration constants.
*   `util/`: URL manipulation, port parsing, and failure tracking utilities.