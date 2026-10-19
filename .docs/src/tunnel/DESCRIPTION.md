<!-- docdaemon ts:2026-10-19T23:27:09Z hash:e45bb01297ab9471 model:openrouter/qwen/qwen3.7-flash -->
# TL;DR
This directory implements the client-side WireGuard tunnel setup, handling device creation and proxy configuration.

# Overview
The `tunnel` package orchestrates the connection between a local client and a remote server by establishing a WireGuard interface and forwarding traffic through a local proxy. It resolves server endpoints, constructs the necessary cryptographic configuration, and manages the lifecycle of the network devices to ensure proper resource cleanup.

# Deep Dive
### Connection Orchestration
The `Tunnel` function serves as the primary entry point, parsing server-assigned client IPs and resolving hostnames to valid IP literals for the WireGuard endpoint. It builds a UAPI-style configuration string using private keys, server public keys, and keepalive settings before initializing the userspace device.

### Endpoint Resolution
To prevent stale or invalid connections, the module includes robust logic for resolving server addresses. It handles both literal IPv4/IPv6 addresses and DNS hostnames, ensuring that the final endpoint is a canonical IP string suitable for peer configuration. This logic was refined to eliminate assumptions about hardcoded loopback addresses.

### Proxy Integration
Once the tunnel is established, a local proxy starts to forward traffic. The module constructs the remote URL for this proxy, intelligently adjusting schemes (e.g., mapping HTTPS to HTTP internally) and ports based on server responses. Error handling ensures that if the proxy fails to start, the WireGuard device is closed immediately to prevent resource leaks.

# Key Interfaces
- `Tunnel`: Orchestrates the full connection lifecycle including device creation and proxy startup.
- `resolveServerIP`: Resolves hostnames or parses IP literals into canonical strings for WireGuard peers.
- `buildWireGuardConfig`: Generates the UAPI configuration string with keys, allowed IPs, and keepalives.
- `buildRemoteURL`: Constructs the proxy target URL, handling scheme and port adjustments.

# Dependencies
- `//src/internal/util`: Internal utility functions.
- `//src/proxy`: Local proxy logic implementation.
- `//types`: Shared type definitions.
- `//wireguard`: WireGuard integration layer.
- External: `zerolog` for structured logging, `wgctrl` for configuration management.

# Subcomponents
- `BUILD.bazel`: Bazel build targets for the library and tests.
- `tunnel.go`: Core implementation of tunnel setup and configuration.
- `tunnel_test.go`: Unit tests for address resolution and error handling.