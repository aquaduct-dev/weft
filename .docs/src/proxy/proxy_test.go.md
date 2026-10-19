<!-- docdaemon ts:2026-10-19T23:25:51Z hash:413e9033d074c751 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains the Ginkgo/Gomega test suite for the `proxy` package, validating tunnel creation, protocol forwarding, conflict detection, and modifier parsing.

The tests cover end-to-end functionality for TCP, UDP, and HTTP proxies using `NewProxyManager`. It verifies that traffic is correctly routed from local listeners to remote destinations, including edge cases like concurrent UDP sessions (preventing map-race panics) and `bindIp` enforcement. Conflict resolution logic is tested via `Conflicts()` methods on `TCPProxy`, `UDPProxy`, and `VHostRouteProxy`, ensuring no duplicate tunnels exist by name or address/port combination, while allowing distinct VHosts on shared ports.

Utility functions are validated through `parseModifiers`, which extracts header modifications and redirect flags from URL fragments. Finally, `WGAwareUDPConn` behavior is checked to ensure graceful error handling when underlying gvisor connections close, preventing panics during read operations.