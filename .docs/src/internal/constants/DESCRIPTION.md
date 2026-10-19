<!-- docdaemon ts:2026-10-09T01:41:31Z hash:182afe26ef0fc319 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory contains the Bazel build configuration and source code for the internal constants package, which centralizes default values for the WireGuard subsystem.

## Overview
The `constants` package serves as a single source of truth for static configuration defaults used across the application. It specifically targets network configuration for WireGuard, providing both human-readable string representations and pre-parsed `netip` types to optimize runtime performance. By initializing these values at package load time, the system ensures that parsing errors are caught during startup rather than causing failures in active tunnels. This approach guarantees consistency and reliability for all components relying on these immutable defaults.

## Deep Dive
### Static Configuration Defaults
The package defines several key constants that establish the baseline network topology. `DefaultSubnetString` sets the CIDR notation for the peer subnet (`10.1.0.0/16`), while `DefaultServerIPString` assigns the server's IP address within that range. These strings provide a clear, human-readable reference for documentation and manual configuration overrides.

### Pre-Parsed Network Types
To avoid repeated parsing overhead, the package exposes pre-computed `netip` variables derived from the string constants. `DefaultSubnet` is initialized using `netip.MustParsePrefix`, and `DefaultServerIP` uses `netip.MustParseAddr`. These functions panic if the hardcoded strings are malformed, shifting validation responsibility to the initialization phase. This design choice ensures that any downstream package accessing these variables receives valid, ready-to-use network addresses without needing to handle potential parse errors.

## Key Interfaces
- `DefaultSubnetString`: The default CIDR notation for the WireGuard peer subnet.
- `DefaultServerIPString`: The default IP address assigned to the server interface.
- `DefaultSubnet`: Pre-parsed `netip.Prefix` for the default subnet.
- `DefaultServerIP`: Pre-parsed `netip.Addr` for the default server IP.

## Dependencies
- `github.com/aquaduct-dev/weft/src/internal/constants` (internal import)
- Standard library `netip` package

## Subcomponents
- `BUILD.bazel`: Bazel build rule definition.
- `constants.go`: Source file containing constant definitions and parsed variables.