<!-- docdaemon ts:2026-10-09T01:41:55Z hash:af0eb76b43f79439 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `src/internal` directory houses the core infrastructure for the WireGuard subsystem, including centralized configuration constants and low-level network utilities.

## Overview
This package provides the foundational building blocks required for stable tunnel management and network topology definition. By centralizing static defaults in `constants`, it ensures that all components operate against a consistent set of immutable values, preventing configuration drift. The `util` package complements this by offering robust helpers for URL manipulation and transient failure tracking, which are critical for maintaining connection stability during upstream outages. Together, these subpackages decouple low-level operational concerns from business logic, promoting reliability and testability across the application.

## Deep Dive
### Static Configuration Defaults
The `constants` package acts as the single source of truth for network topology. It defines human-readable string representations for the default peer subnet (`10.1.0.0/16`) and server IP, alongside pre-parsed `netip` types. These parsed variables are initialized at package load time using `MustParse` functions, which panic on malformed input. This design shifts validation to startup, ensuring that any downstream component accessing these values receives valid, ready-to-use network addresses without handling parse errors.

### Failure Tracking and Network Utilities
The `util` package implements a sliding window counter via `FailureTracker` to mitigate transient upstream errors. By recording failure timestamps, it prevents premature tunnel teardowns during brief restarts or outages, resetting only after a threshold is exceeded or manually upon success. Complementary functions like `EnsurePort` inject standard defaults (80/443) into URLs while rejecting ambiguous schemes, and `ParsePort` extracts integer ports with strict validation. `RewriteHost` allows safe hostname updates while preserving existing port configurations, ensuring consistency in proxy operations.

## Key Interfaces
- `DefaultSubnetString`: Default CIDR notation for the WireGuard peer subnet.
- `DefaultServerIPString`: Default IP address assigned to the server interface.
- `DefaultSubnet`: Pre-parsed `netip.Prefix` for the default subnet.
- `DefaultServerIP`: Pre-parsed `netip.Addr` for the default server IP.
- `type FailureTracker struct`: Sliding window counter for upstream dial failures.
- `func EnsurePort(url *url.URL) error`: Validates and injects default ports into URLs.
- `func ParsePort(host string, defaultPort int) (int, error)`: Extracts port from host string.
- `func RewriteHost(url *url.URL, newHost string)`: Updates URL hostname while keeping the port.

## Dependencies
- Standard library `netip`
- Standard library `net/url`
- Standard library `time`

## Subcomponents
- `constants/`
- `util/`