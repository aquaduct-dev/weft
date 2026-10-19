<!-- docdaemon ts:2026-10-19T23:25:49Z hash:745b75a90cb9b8ad model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the default network configuration constants for the WireGuard interface.

### Purpose
The `constants` package provides immutable defaults for the internal WireGuard setup. It ensures that the subnet and server IP address are consistent across the application by exposing both human-readable string representations and pre-parsed `netip` types.

### Key Definitions

**String Constants**
*   `DefaultSubnetString`: The CIDR notation for the default WireGuard subnet (`10.1.0.0/16`).
*   `DefaultServerIPString`: The specific IP address assigned to the server within that subnet (`10.1.0.1`).

**Parsed Variables**
*   `DefaultSubnet`: A `netip.Prefix` parsed from `DefaultSubnetString`. This is used for programmatic subnet checks.
*   `DefaultServerIP`: A `netip.Addr` parsed from `DefaultServerIPString`. This is used for direct IP comparisons.

### Implementation Details
The parsed variables (`DefaultSubnet`, `DefaultServerIP`) are initialized at package load time using `netip.MustParse...`. This guarantees that any invalid configuration in the string constants will cause an immediate panic during startup, rather than failing silently or later in the execution flow.

Historically, this package also exposed a redacted private key constant for logging safety. That constant was removed because it was no longer used after the `sanitizeConfig` function was eliminated. Current tests verify that `DefaultServerIP` correctly resides within `DefaultSubnet`.