<!-- docdaemon ts:2026-10-19T23:25:46Z hash:24143e8f38a6c3d4 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `tunnel` CLI command to establish and manage persistent WireGuard tunnels between local and remote endpoints.

The `tunnelCmd` Cobra command parses a server URL containing a connection secret, optional TLS flags, and pairs of local/remote URLs. It iterates over these pairs, invoking `startTunnel` for each to create independent tunnel instances. This design supports multi-tunnel setups, where explicit names are optional (defaulting to a SHA-256 hash of the local/remote pair).

Key responsibilities include:
*   **Authentication**: Calls `auth.Login` using the connection secret from the server URL. Supports optional `--server-fingerprint` pinning for the initial handshake.
*   **Tunnel Provisioning**: Generates a WireGuard private key, sends a `ConnectRequest` to the server's `/connect` endpoint, and receives assigned IP/port details.
*   **Proxy Management**: Initializes a `proxy.ProxyManager` and starts the `tunnel.Tunnel` instance, optionally injecting custom TLS certificates provided via `--tls-cert` and `--tls-key`.
*   **Health Monitoring**: Launches a background `client.HealthMonitor` with adaptive retry logic to detect connectivity failures.
*   **Graceful Shutdown**: Registers cleanup functions that stop health checks, notify the server via `/shutdown`, and close the WireGuard device upon receiving OS signals.