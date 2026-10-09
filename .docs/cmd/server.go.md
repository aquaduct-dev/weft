<!-- docdaemon ts:2026-10-09T01:40:05Z hash:676301406f68afe8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the `server` command for the Weft CLI, handling server initialization, IP discovery, and lifecycle management.

### Purpose
The `cmd/server.go` package implements the Cobra command responsible for starting the Weft server. It manages configuration flags, discovers network interfaces, binds to specific IPs or interfaces, and handles graceful shutdowns via signal interception.

### Key Functions

*   **`discoverPublicIP`**: Attempts to identify a public IPv4 address by querying an external Hetzner service and scanning local network interfaces. It filters out loopback, private, and link-local addresses. If strict binding is enabled, it validates the chosen IP by attempting a TCP listen; otherwise, it falls back to `0.0.0.0`.
*   **`isLikelyPublic`**: Helper function that validates if a parsed IP address is globally routable (not loopback, private, link-local, or unspecified).
*   **`serverCmd`**: The main Cobra command execution logic. It parses flags for email, port, bind IP, and secrets. It optionally binds the discovered IP to a specific network interface using `netlink`, writes the connection secret to a file if requested, and starts the HTTPS server.
*   **`init`**: Registers the `server` command with the root CLI and defines all available flags, including `--bind-ip`, `--port`, `--secret-file`, `--cloudflare-token`, and `--use-strict-bind-ip`.

### Integration
This file sits in the `cmd` package, acting as the entry point for the server binary. It relies on the `server` package (`github.com/aquaduct-dev/weft/src/server`) for the actual HTTP/HTTPS server implementation and uses `netlink` for low-level network interface manipulation.