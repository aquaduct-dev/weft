<!-- docdaemon ts:2026-10-09T01:40:05Z hash:8792bfd50dd55fe2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `tunnel` CLI command to establish and manage persistent Weft tunnels between local and remote endpoints.

### Purpose
It handles argument parsing, authentication with the Weft server, WireGuard key generation, and tunnel lifecycle management (start/stop). It supports multiple simultaneous tunnels and integrates health monitoring.

### Key Functions
- **`init`**: Registers the `tunnel` subcommand with flags for naming, retries, TLS certificates, and server fingerprint pinning.
- **`tunnelCmd.Run`**: Orchestrates the main flow: parses the connection URL, iterates over local/remote pairs, calls `startTunnel`, and waits for OS signals to trigger cleanup.
- **`startTunnel`**: Authenticates via `auth.Login`, generates a WireGuard private key, sends a `ConnectRequest` to the server, creates the tunnel device, and starts a background health monitor. Returns a cleanup function that shuts down the monitor, notifies the server, and closes the device.

### Integration
Depends on `auth`, `client`, `proxy`, `tunnel`, and `wireguard` packages. Interacts with the server API at `/login`, `/connect`, `/healthcheck`, and `/shutdown`.