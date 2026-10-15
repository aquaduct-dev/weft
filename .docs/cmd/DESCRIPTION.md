<!-- docdaemon ts:2026-10-15T20:43:06Z hash:f60e37faa415821c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `cmd` package defines the Weft CLI entry point, aggregating subcommands for server management, tunneling, and proxying.

## Overview
This directory serves as the primary interface for interacting with the Weft system via the command line. It implements a Cobra-based command tree that handles global configuration, authentication flows, and lifecycle management for various network operations. By centralizing argument parsing and signal handling here, it keeps business logic isolated in internal packages while providing a consistent user experience.

## Deep Dive
### Root Configuration
The `root.go` file establishes the base `weft` command, initializing the logging subsystem and managing global flags like verbosity. It acts as the execution hub, delegating to specific subcommands while ensuring consistent error reporting via zerolog.

### Server Management
`server.go` implements the `server` command, responsible for starting the Weft HTTP/HTTPS service. It handles IP discovery, binding to network interfaces using netlink, and graceful shutdowns. This command also manages secret generation and Cloudflare token integration for DNS challenges.

### Tunnel Operations
`tunnel.go` and `list.go` handle persistent WireGuard tunnels. The `tunnel` command authenticates users, generates keys, and maintains health monitors for local-to-remote connections. Conversely, `list.go` retrieves active tunnel statistics from the server, formatting them for display.

### Proxying and Probing
`proxy.go` enables one-off source-to-destination proxies without a full server instance, supporting static TLS or ACME. `probe.go` verifies server connectivity for ACME challenges, optionally manipulating network interfaces to bind specific IPs during validation.

## Key Interfaces
- `Execute()`: Main entry point for CLI execution.
- `rootCmd`: Base Cobra command with global flag registration.
- `serverCmd`: Command handler for starting the Weft server.
- `tunnelCmd`: Command handler for establishing and managing tunnels.
- `proxyCmd`: Command handler for running ephemeral proxies.
- `listCmd`: Command handler for listing active tunnels.
- `probeCmd`: Command handler for ACME challenge verification.

## Dependencies
- github.com/spf13/cobra (CLI framework)
- github.com/rs/zerolog (Structured logging)
- github.com/vishvananda/netlink (Network interface manipulation)
- Internal auth, client, proxy, server, and tunnel packages

## Subcomponents
- root.go: Global CLI setup and logging initialization.
- server.go: Server startup, IP discovery, and signal handling.
- tunnel.go: Persistent tunnel creation and health monitoring.
- list.go: Active tunnel retrieval and display.
- proxy.go: Ephemeral source-to-destination proxy management.
- probe.go: ACME challenge connectivity verification.
- BUILD.bazel: Bazel build target definition.