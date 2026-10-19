<!-- docdaemon ts:2026-10-19T23:25:51Z hash:347e6738292b0c97 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the `Proxy` interface and its concrete implementations (`TCPProxy`, `UDPProxy`, `VHostRouteProxy`) along with WireGuard-aware network connection wrappers.

The `Proxy` interface standardizes traffic forwarding, providing methods for lifecycle management (`Close`), identification (`Name`, `InstanceId`), and metrics (`BytesTx`, `BytesRx`). It also includes `Conflicts` to detect port or address collisions between different proxy types.

**Concrete Implementations:**
*   **`TCPProxy`**: Manages a `net.Listener` for TCP streams. It tracks byte counts atomically and uses a `util.FailureTracker` (referenced in comments) to handle transient upstream dial failures gracefully without tearing down tunnels immediately.
*   **`UDPProxy`**: Wraps a `WGAwareUDPConn` for UDP traffic. It resolves endpoints from either the active connection or a static configuration address.
*   **`VHostRouteProxy`**: Handles HTTP/HTTPS virtual host routing. It delegates metrics to a `meter.MeteredHTTPHandler` and defines conflict logic based on IP, port, hostname, HTTPS status, and path rewrite rules.

**WireGuard Integration:**
The file provides `WGAwareUDPConn` and helper functions (`WGAwareUDPDial`, `WGAwareUDPListen`, `WGAwareTCPDial`, `WGAwareTCPListen`) that route traffic through the gVisor NetStack if the destination is within the default WireGuard subnet. The `ReadFromUDP` method safely handles nil addresses returned by gVisor on connection closure to prevent panics.