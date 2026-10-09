<!-- docdaemon ts:2026-10-09T01:40:46Z hash:814eba3e640c0ea6 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a thread-safe, in-memory store for managing tunnel peers and their associated IP address allocations.

## Purpose
`InMemoryTunnelStore` provides the backend storage for peer state within the server. It handles concurrent access to peer records, last-seen timestamps, and IP address tracking using a subnet defined by `constants.DefaultSubnet`.

## Key Types
- **`InMemoryTunnelStore`**: The main struct containing maps for peers (`map[string]Peer`), last-seen times (`map[string]time.Time`), and used IPs (`map[netip.Addr]bool`). It uses an `RWMutex` to ensure safe concurrent reads and writes.

## Important Functions
- **`NewInMemoryTunnelStore`**: Initializes the store with empty maps and the default subnet configuration.
- **`CreatePeer`**: Atomically registers a new peer if it doesn't exist. It allocates an IP from the subnet via `allocateIPLocked`, invokes the provided factory function to create the `Peer` object, and updates the last-seen timestamp. If the peer already exists, it returns the existing record without allocating a new IP.
- **`GetFreeIP` / `allocateIPLocked`**: Reserves the next available IP address in the subnet, skipping the host address (if unused) and the broadcast address. Returns an error if the subnet is exhausted.
- **`ReleaseIP`**: Marks an IP address as free by removing it from the `usedIPs` map.
- **Peer CRUD Operations**: `GetPeer`, `SetPeer`, `DeletePeer`, and `GetAllPeers` manage the peer registry.
- **Last-Seen Management**: `GetLastSeen`, `SetLastSeen`, `DeleteLastSeen`, and `GetAllLastSeen` manage peer activity timestamps.