<!-- docdaemon ts:2026-10-30T02:44:47Z hash:8b5e71b32226fda0 model:openrouter/qwen/qwen3.7-flash -->
# cmd

## TL;DR
This directory implements the Weft command-line interface, providing subcommands to manage proxies, tunnels, and server instances.

## Overview
The `cmd` package serves as the entry point for the Weft application, aggregating core CLI logic into a cohesive toolset. It leverages Cobra for command structure and Zerolog for structured output, enabling operators to configure network routing, establish secure WireGuard tunnels, and run local proxy services. The code handles authentication flows, TLS certificate management, and graceful lifecycle transitions for long-running background processes.

## Deep Dive

### Root Configuration
`root.go` initializes the global command tree, registering persistent flags like `--verbose` that control logging verbosity across all subcommands. It ensures the logging subsystem is initialized before any subcommand executes, standardizing error reporting and debug output.

### Server Management
`server.go` orchestrates the bastion host startup, handling IP discovery, ACME challenge listener initialization, and connection secret persistence. It supports binding to specific interfaces via `netlink` and enforces strict bind policies to prevent wildcard exposure. Graceful shutdown is managed through signal handlers, ensuring active connections are drained within a timeout window.

### Tunnel Provisioning
`tunnel.go` establishes persistent WireGuard tunnels by authenticating with the server, provisioning endpoints, and starting proxy managers. It includes health monitoring with adaptive retry logic and supports multi-tunnel configurations. Recent fixes address 404 handling during janitor cleanup to prevent premature client termination.

### Proxy and List Operations
`proxy.go` creates one-off source-to-destination proxies without requiring a full server instance, supporting static or ACME-managed TLS. `list.go` retrieves active tunnel states from the server, parsing credentials from URLs and displaying results in a human-readable tabular format. `probe.go` verifies server connectivity for ACME challenges, temporarily manipulating network interfaces if required.

## Key Interfaces
*   `rootCmd`: The base Cobra command defining global flags and execution entry points.
*   `proxyCmd`: Subcommand for creating ephemeral URL proxies with optional TLS termination.
*   `tunnelCmd`: Subcommand for establishing and managing persistent WireGuard tunnels.
*   `serverCmd`: Subcommand for running the Weft bastion server with ACME support.
*   `listCmd`: Subcommand for querying and displaying active tunnel information.
*   `probeCmd`: Subcommand for validating ACME challenge reachability on specific hosts.

## Dependencies
*   `github.com/spf13/cobra`: Command-line interface framework.
*   `github.com/rs/zerolog`: Structured logging library.
*   `github.com/vishvananda/netlink`: Network interface manipulation.
*   Internal packages: `auth`, `client`, `logging`, `proxy`, `server`, `tunnel`.

## Subcomponents
*   `BUILD.bazel`: Bazel build configuration for the CLI package.
*   `list.go`: Active tunnel listing implementation.
*   `probe.go`: ACME challenge connectivity verification.
*   `proxy.go`: Ephemeral proxy creation logic.
*   `root.go`: Global command structure and flag registration.
*   `server.go`: Bastion server startup and lifecycle management.
*   `tunnel.go`: Persistent tunnel establishment and health monitoring.