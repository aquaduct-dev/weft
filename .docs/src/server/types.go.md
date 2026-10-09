<!-- docdaemon ts:2026-10-09T01:40:49Z hash:85c37a787a8c770c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the core data structures and interfaces for managing WireGuard tunnel peers, IP allocation, and network dataplane operations.

### Purpose
`types.go` establishes the contract between the server's control plane and its networking components. It abstracts peer state management and dataplane interactions to ensure thread-safe operation and clear separation of concerns.

### Key Types

#### `Peer`
Represents a connected tunnel client. It stores:
- **Identity**: The WireGuard public key (`PublicKey`).
- **Network**: Assigned internal IP (`IP`) and proxy port (`TunnelProxyPort`).
- **Routing**: Source (`ProxiedUpstream`) and destination (`DstURL`) URLs for traffic forwarding.

#### `TunnelStore`
An interface for managing peer lifecycle and IP address pools. Implementations must be thread-safe.
- **CRUD Operations**: `GetPeer`, `SetPeer`, `DeletePeer`, `GetAllPeers`.
- **State Tracking**: `GetLastSeen`, `SetLastSeen`, `DeleteLastSeen` for monitoring active tunnels.
- **IP Management**: `GetFreeIP` and `ReleaseIP` handle dynamic IP assignment from an internal pool.
- **Atomic Creation**: `CreatePeer` ensures that concurrent connection requests for the same tunnel name do not leak IPs by atomically checking existence, allocating an IP, and storing the peer via a factory function.

#### `Dataplane`
An interface for interacting with the underlying network infrastructure.
- **WireGuard Sync**: `UpdateWireGuardConfig` synchronizes device state with current peers.
- **Proxy Management**: `StartProxy` and `CloseProxy` manage listener lifecycles. `GetProxyCounters` provides traffic statistics.
- **Device Access**: `GetDevice` and `GetPrivateKey` expose low-level WireGuard components.
- **ACME Integration**: `RegisterACMERedirect` handles HTTP challenge redirections for certificate validation, requiring prior DNS validation by the caller.

#### `ProxyCounters`
Holds cumulative byte counts (`Tx`, `Rx`) and a unique `InstanceId` for each active proxy instance.