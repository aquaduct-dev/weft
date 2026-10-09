<!-- docdaemon ts:2026-10-09T01:48:05Z hash:066c9db614d6f168 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory defines the command-line interface for the Weft proxy application using Cobra.

## Overview
The `cmd` package serves as the entry point for the Weft binary, translating user intent into specific operational modes. It aggregates core functionality including server management, tunnel creation, and network probing into a cohesive CLI structure. By delegating heavy lifting to internal packages like `auth`, `proxy`, and `server`, it maintains a clean separation between interface logic and business rules.

## Deep Dive
### Root Command Structure
`root.go` establishes the base `weft` command, initializing the global logging subsystem via `logging.Init()`. It handles persistent flags such as `--verbose`, which toggates debug-level WireGuard logs. The `Execute()` function orchestrates the command tree execution, ensuring fatal errors are logged via `zerolog` before exit.

### Server Lifecycle
`server.go` implements the `server` subcommand, responsible for starting the HTTPS listener. It includes logic to discover public IPs via Hetzner services or local interface scanning, with optional strict binding validation. The command manages graceful shutdowns and supports writing connection secrets to files for client configuration.

### Tunnel Management
`tunnel.go` handles persistent connections between local and remote endpoints. It authenticates users, generates WireGuard keys, and initiates tunnels via the `/connect` API. A background health monitor ensures connectivity, while signal handlers trigger cleanup routines to notify the server and close devices.

### Proxying and Probing
`proxy.go` enables temporary one-off proxying between URLs, blocking until interrupted by SIGINT/SIGTERM. `probe.go` verifies ACME challenge connectivity, optionally manipulating network interfaces via `netlink` to bind specific IPs. `list.go` retrieves active tunnel statistics from the server, formatting output as a human-readable table.

## Key Interfaces
- `rootCmd`: The primary Cobra command instance defining the application root.
- `Execute()`: Main entry point that runs the command tree and handles errors.
- `serverCmd`: Cobra command for initializing and running the Weft server.
- `tunnelCmd`: Cobra command for establishing and managing persistent tunnels.
- `proxyCmd`: Cobra command for creating temporary URL proxies.
- `probeCmd`: Cobra command for testing ACME challenge reachability.
- `listCmd`: Cobra command for listing active tunnel statistics.

## Dependencies
- github.com/spf13/cobra (CLI framework)
- github.com/rs/zerolog (Structured logging)
- github.com/aquaduct-dev/weft/src/auth (Authentication logic)
- github.com/aquaduct-dev/weft/src/proxy (Proxy implementation)
- github.com/aquaduct-dev/weft/src/server (Server implementation)
- github.com/aquaduct-dev/weft/src/tunnel (Tunnel management)
- github.com/vishvananda/netlink (Network interface manipulation)

## Subcomponents
- BUILD.bazel: Bazel build target definition.
- root.go: Base command and global flag handling.
- server.go: Server initialization and IP discovery.
- tunnel.go: Persistent tunnel lifecycle management.
- proxy.go: Temporary proxy creation.
- probe.go: ACME challenge connectivity verification.
- list.go: Active tunnel status retrieval.