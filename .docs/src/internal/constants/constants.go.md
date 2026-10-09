<!-- docdaemon ts:2026-10-09T01:40:19Z hash:002ab193c8bdfb75 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines static configuration constants and pre-parsed network addresses for the WireGuard subsystem.

## Purpose
The `constants` package centralizes default values used across the application to ensure consistency in network configuration. It provides both string representations for human-readable defaults and parsed `netip` types for efficient programmatic use, avoiding repeated parsing overhead at runtime.

## Key Definitions

### Constants
- **`DefaultSubnetString`**: The default CIDR notation for the WireGuard peer subnet (`10.1.0.0/16`).
- **`DefaultServerIPString`**: The default IP address assigned to the server interface within the subnet.
- **`WGPrivateKeyRedacted`**: A placeholder string used exclusively for logging purposes to prevent accidental exposure of actual private keys. Never use this value for cryptographic operations.

### Variables
- **`DefaultSubnet`**: A pre-parsed `netip.Prefix` derived from `DefaultSubnetString`. This variable is initialized at package load time using `netip.MustParsePrefix`, ensuring that any parsing errors occur during startup rather than at runtime.
- **`DefaultServerIP`**: A pre-parsed `netip.Addr` derived from `DefaultServerIPString`. Similarly initialized via `netip.MustParseAddr` for immediate availability.

## Usage Notes
These variables are intended for read-only access by other packages configuring the WireGuard tunnel. Because they rely on `MustParse` functions, the package initialization will panic if the hardcoded strings are malformed, making them suitable for immutable configuration defaults.