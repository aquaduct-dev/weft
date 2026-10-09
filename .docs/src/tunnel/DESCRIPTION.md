<!-- docdaemon ts:2026-10-09T01:42:10Z hash:312e8b544ac9cebd model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements the core logic for establishing client-side WireGuard tunnels and managing associated proxy connections.

## Overview
The `tunnel` package provides the infrastructure to connect Weft clients to remote servers using WireGuard. It handles the lifecycle of the userspace network device, including configuration generation, IP resolution, and secure transport setup. By abstracting the complexity of tunnel creation, it allows higher-level components to focus on traffic routing and policy enforcement.

## Deep Dive
### Tunnel Orchestration
The primary entry point is the `Tunnel` function, which coordinates the entire connection process. It accepts a `ConnectResponse` from the server, extracts necessary parameters like assigned IPs and keys, and initializes the WireGuard interface. This function serves as the bridge between the control plane (server response) and the data plane (network device).

### Configuration Generation
Helper functions construct the specific WireGuard configuration required for the connection. They combine the client's private key with the server's public key and endpoint details. The logic ensures that the resulting configuration adheres to the protocol requirements defined in the `types` package, supporting various transport mechanisms.

### Proxy Integration
Once the tunnel is established, the package initiates a proxy manager to route traffic through the secure channel. It builds the remote URL based on the negotiated protocol (TCP, HTTP, HTTPS, or UDP) and starts the proxy service. This integration ensures that all subsequent network requests are encapsulated within the WireGuard tunnel.

## Key Interfaces
- `Tunnel`: Main function to establish the client-side connection and start the proxy.

## Dependencies
- Internal: `//src/internal/util`, `//src/proxy`, `//types`, `//wireguard`
- External: `@com_github_rs_zerolog//log`, `@com_zx2c4_golang_wireguard_wgctrl//wgtypes`

## Subcomponents
- `BUILD.bazel`: Bazel build rules for the Go library.
- `tunnel.go`: Implementation of the tunnel establishment logic.