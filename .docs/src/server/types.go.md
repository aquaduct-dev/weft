<!-- docdaemon ts:2026-10-19T23:25:59Z hash:e56b5bb12814af28 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the core data structures and interfaces for managing WireGuard peers, IP allocation, and proxy state in the server.

### Peer Management
The `Peer` struct holds client metadata, including the WireGuard public key, assigned internal IP, and routing details (`ProxiedUpstream`, `DstURL`). The `TunnelStore` interface manages peer lifecycle and IP address pools. It includes atomic operations like `CreatePeer` to prevent IP leaks during concurrent connection requests, ensuring that only one peer is created per tunnel name while safely allocating a unique IP.

### Networking & Proxying
The `Dataplane` interface abstracts the underlying networking components. It handles synchronization of WireGuard configurations via `UpdateWireGuardConfig` and manages proxy listeners through `StartProxy` and `CloseProxy`. It also exposes metrics via `GetProxyCounters` and provides access to the underlying device and private key.

### ACME Integration
Recent updates added support for automated TLS certificate management. `Dataplane` now includes methods to set ACME email and cache paths, list cached certificates, and track issuance failures. The `RegisterACMERedirect` method facilitates peer-to-peer ACME challenge redirects, allowing the server to route validation requests to specific peers based on DNS configuration.