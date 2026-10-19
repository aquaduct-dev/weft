<!-- docdaemon ts:2026-10-19T23:26:00Z hash:c51e09f80391f5be model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the client-side WireGuard tunnel setup, handling device creation and proxy configuration.

The `Tunnel` function orchestrates the connection by parsing the server-assigned client IP, resolving the server endpoint, and constructing a WireGuard configuration. It creates a userspace device bound to the assigned address and starts a local proxy to forward traffic through the tunnel.

Key internal helpers include:
- `resolveServerIP`: Resolves hostnames or parses IP literals from the server address, ensuring the WireGuard endpoint is valid.
- `buildWireGuardConfig`: Generates the UAPI-style configuration string using the private key, server public key, allowed IPs (defaulting to 0.0.0.0/0), and keepalive settings.
- `buildRemoteURL`: Constructs the remote URL for the proxy, adjusting schemes (e.g., mapping HTTPS to HTTP internally) and ports based on the response.

Error handling ensures that if proxy startup fails, the WireGuard device is properly closed to prevent resource leaks.