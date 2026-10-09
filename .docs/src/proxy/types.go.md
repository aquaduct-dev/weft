<!-- docdaemon ts:2026-10-09T01:40:25Z hash:41b48339b8c62c52 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the core proxy abstractions and WireGuard-aware networking utilities for handling TCP, UDP, and virtual-host-based traffic forwarding.

## Purpose
It establishes a unified `Proxy` interface for managing different traffic types (TCP, UDP, VHost) and provides adapters to route connections through either standard network stacks or a WireGuard userspace device (`gvisor`).

## Key Types

### Proxy Interface
Defines the contract for all forwarders, including lifecycle management (`Close`), conflict detection (`Conflicts`), and metrics tracking (`BytesTx`, `BytesRx`).

### Concrete Implementations
- **TCPProxy**: Manages transparent TCP layer-4 forwarding with failure tracking to prevent tunnel teardown during transient outages.
- **UDPProxy**: Handles UDP traffic using a `WGAwareUDPConn` wrapper to support both standard and WireGuard-specific sockets.
- **VHostRouteProxy**: Implements layer-7 HTTP/HTTPS routing based on host, port, and path rewrite rules, delegating metrics to a metered handler.

### Networking Utilities
- **WGAwareUDPConn**: A dual-mode connection wrapper that selects between `gonet.UDPConn` (WireGuard) and `net.UDPConn` based on destination IP.
- **Dial/Listen Functions**: `WGAwareUDPDial`, `WGAwareUDPListen`, `WGAwareTCPDial`, and `WGAwareTCPListen` automatically detect if an address belongs to the WireGuard subnet and route traffic accordingly.