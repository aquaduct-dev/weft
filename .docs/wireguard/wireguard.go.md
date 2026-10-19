<!-- docdaemon ts:2026-10-19T23:26:03Z hash:d75795477c49e33f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file wraps the wireguard-go library to manage userspace TUN devices and serialize WireGuard configuration.

### Core Types
*   **`UserspaceDevice`**: Holds the `device.Device`, `netstack.Net`, and `tun.Device`. It represents a running WireGuard interface with an integrated TCP/IP stack.
*   **`IPBind`**: Implements `conn.Bind` to restrict UDP traffic to a specific local IP address, unlike the default bind which listens on all interfaces.
*   **`UdpEndpoint`**: A wrapper around `net.UDPAddr` implementing `conn.Endpoint` for internal routing.

### Key Functions
*   **`NewUserspaceDevice`**: Initializes a new device using `netstack.CreateNetTUN`. It applies the provided IPC config string and brings the device up. If `bindIP` is specified (and not `0.0.0.0`), it uses `IPBind`; otherwise, it falls back to the system default bind. The log level adapts to the package-level `Verbose` flag.
*   **`ConfigToString`**: Serializes a `wgtypes.Config` into the WireGuard UAPI text format. It handles private keys, listen ports, and peers. Crucially, it omits `replace_peers=true` to allow incremental peer updates, preserving learned endpoints during roaming. Removed peers are signaled via `remove=true` without other attributes.
*   **`GeneratePrivateKey`**: Creates a new valid WireGuard private key.