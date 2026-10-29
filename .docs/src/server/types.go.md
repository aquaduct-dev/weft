<!-- docdaemon ts:2026-10-29T21:04:44Z hash:9aa9fa7fc680cd3f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the core data structures and interfaces for managing WireGuard peers, IP allocation, and proxy state within the server.

The `Peer` struct tracks individual tunnel clients, storing their WireGuard public key, assigned internal IP, and routing details (`ProxiedUpstream`, `DstURL`). It serves as the primary unit of state for active connections.

`TunnelStore` abstracts peer lifecycle management and IP pool operations. It ensures thread-safe access to peer records and last-seen timestamps. Crucially, it provides `CreatePeer`, an atomic operation that prevents IP leaks during concurrent `/connect` requests by combining lookup, allocation, and storage into a single step.

`Dataplane` interfaces with the underlying networking stack. It handles synchronizing WireGuard configurations, starting/stopping HTTP proxies, and managing TLS certificates via ACME. Methods like `GetPrivateKey` and `SetACMEEmail` expose sensitive configuration without exposing raw credentials directly in the interface contract.

`ProxyCounters` aggregates traffic statistics (Tx/Rx bytes) per proxy instance, supporting observability and usage reporting.