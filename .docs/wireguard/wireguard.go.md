<!-- docdaemon ts:2026-10-09T01:40:02Z hash:617522a1faf16799 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a Go wrapper around the `wireguard-go` library to manage userspace WireGuard devices, including custom network binding and configuration serialization.

### Purpose
The package abstracts the low-level `wireguard-go` components (`device`, `tun`, `conn`) into a higher-level API. It handles the lifecycle of creating a TUN interface, binding UDP sockets to specific IPs, and applying WireGuard configurations via the IPC protocol.

### Key Types
- **`UserspaceDevice`**: Aggregates the underlying `device.Device`, `netstack.Net`, and `tun.Device`. This is the primary handle for interacting with the tunnel.
- **`IPBind`**: Implements `conn.Bind` to restrict the WireGuard socket to a specific local IP address, rather than listening on all interfaces.
- **`UdpEndpoint`**: A helper struct that adapts standard `net.UDPAddr` to the `conn.Endpoint` interface required by the WireGuard device.

### Important Functions
- **`NewUserspaceDevice`**: Initializes a new WireGuard instance. It creates a virtual TUN device using `netstack`, configures the bind interface (custom or default), applies the IPC configuration string, and brings the device up.
- **`ConfigToString`**: Serializes a `wgtypes.Config` struct into the WireGuard UAPI format (key-value pairs). It correctly handles private keys, peers, allowed IPs, endpoints, and removal flags.
- **`GeneratePrivateKey`**: Generates a new cryptographic private key for use in configurations.

### Usage Notes
Set the package-level `Verbose` boolean before starting the device to control log verbosity. The `bindIP` parameter in `NewUserspaceDevice` allows binding to a specific interface IP; pass an empty string or `"0.0.0.0"` for default behavior.