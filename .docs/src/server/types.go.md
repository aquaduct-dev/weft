<!-- docdaemon ts:2026-10-30T02:43:08Z hash:c51b49dee7b7b842 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the core interfaces and data structures for managing tunnel peers, IP allocation, and network dataplane operations.

`Peer` struct holds client state including WireGuard keys, assigned IPs, and proxy routing details. `TunnelStore` abstracts peer lifecycle management and IP pool allocation. It includes `CreatePeer`, an atomic operation introduced to prevent IP leaks during concurrent `/connect` requests where race conditions previously caused address exhaustion.

`Dataplane` interface manages the underlying networking stack, specifically WireGuard configuration synchronization and HTTP proxy listeners. It also handles ACME certificate issuance, exposing methods to manage TLS certs and challenge listeners. Recent changes ensure the ACME challenge port remains open across sibling bastions to support round-robin DNS probes and peer-to-peer challenge redirection, preventing connection refused errors during certificate acquisition.

`ProxyCounters` tracks cumulative traffic statistics (Tx/Rx) per proxy instance.