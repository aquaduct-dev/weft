<!-- docdaemon ts:2026-10-09T01:48:04Z hash:02a60fa58a74aaa7 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory provides a Go wrapper around the `wireguard-go` library to manage userspace WireGuard devices with custom network binding and configuration serialization.

## Overview
The `wireguard` package abstracts low-level components like `device`, `tun`, and `conn` into a higher-level API for lifecycle management. It handles TUN interface creation, UDP socket binding to specific IPs, and configuration application via the IPC protocol. This allows consumers to integrate WireGuard tunnels without managing the underlying C/Go interop details directly.

## Deep Dive
### Device Lifecycle Management
The core responsibility is initializing and controlling the tunnel state. `NewUserspaceDevice` orchestrates the setup of the virtual TUN device using `netstack`, configures the bind interface, applies the initial IPC configuration string, and brings the device up. The `UserspaceDevice` struct serves as the primary handle, aggregating the underlying device logic, network stack, and TUN interface.

### Network Binding
To support multi-homed or restricted environments, the package implements `IPBind`, which restricts the WireGuard socket to a specific local IP address rather than listening on all interfaces. This ensures traffic only flows through the intended network interface. Helper types like `UdpEndpoint` adapt standard `net.UDPAddr` structures to the `conn.Endpoint` interface required by the WireGuard device layer.

### Configuration Handling
Configuration management is handled through serialization and generation utilities. `ConfigToString` converts `wgtypes.Config` structs into the WireGuard UAPI format (key-value pairs), correctly handling private keys, peers, allowed IPs, endpoints, and removal flags. `GeneratePrivateKey` provides a convenient way to create new cryptographic keys for dynamic configurations.

## Key Interfaces
- `UserspaceDevice`: Aggregates `device.Device`, `netstack.Net`, and `tun.Device` for tunnel interaction.
- `IPBind`: Implements `conn.Bind` to restrict sockets to a specific local IP.
- `UdpEndpoint`: Adapts `net.UDPAddr` to the `conn.Endpoint` interface.
- `NewUserspaceDevice`: Initializes a new WireGuard instance with specified bindings.
- `ConfigToString`: Serializes `wgtypes.Config` into UAPI key-value format.
- `GeneratePrivateKey`: Generates a new cryptographic private key.

## Dependencies
- `com_zx2c4_golang_wireguard` (conn, device, tun, tun/netstack, wgtypes)
- `com_zx2c4_golang_wireguard_wgctrl`

## Subcomponents
- `BUILD.bazel`: Bazel build rules for the Go library.
- `wireguard.go`: Main implementation file containing wrappers and helpers.