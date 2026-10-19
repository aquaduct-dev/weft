<!-- docdaemon ts:2026-10-19T23:26:46Z hash:62ab3fa63d2ca124 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package defines immutable default network configuration constants for the internal WireGuard interface.

## Overview
The `constants` package ensures consistency across the application by exposing pre-parsed `netip` types alongside their string representations. By initializing these values at package load time, invalid configurations trigger immediate panics rather than silent failures or runtime errors. This approach guarantees that the subnet and server IP address remain logically valid throughout execution.

## Deep Dive
### Network Defaults
The package exposes two primary string constants: `DefaultSubnetString` (`10.1.0.0/16`) and `DefaultServerIPString` (`10.1.0.1`). These serve as the human-readable source of truth for the WireGuard setup. Corresponding parsed variables, `DefaultSubnet` and `DefaultServerIP`, are derived from these strings using `netip.MustParse...`. This dual exposure allows code to use either convenient string formatting or efficient programmatic IP comparisons.

### Initialization Safety
Parsed variables are initialized during package loading. If the string constants contain malformed data, the initialization fails immediately via panic. This design choice prevents subtle configuration bugs from propagating into the application logic. The system prioritizes early failure over graceful degradation for static configuration values.

### Validation
Tests verify that the parsed values match their string counterparts and that the server IP resides within the defined subnet. This ensures logical integrity between the abstract definitions and their concrete implementations. Unused constants, such as redacted private keys, have been removed to reduce maintenance overhead and clarify the package's scope.

## Key Interfaces
*   `DefaultSubnetString`: CIDR notation for the default WireGuard subnet.
*   `DefaultServerIPString`: Specific IP address assigned to the server.
*   `DefaultSubnet`: Pre-parsed `netip.Prefix` for programmatic subnet checks.
*   `DefaultServerIP`: Pre-parsed `netip.Addr` for direct IP comparisons.

## Dependencies
*   `github.com/aquaduct-dev/weft/src/internal/constants` (self)
*   Standard library `net/netip`

## Subcomponents
*   `BUILD.bazel`: Bazel build rules for the Go library and tests.
*   `constants.go`: Definition of network configuration constants.
*   `constants_test.go`: Validation tests for constant integrity.