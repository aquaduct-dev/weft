<!-- docdaemon ts:2026-10-09T01:40:44Z hash:d395750430b19362 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `Janitor` component, verifying its ability to sweep stale tunnels and manage lifecycle states.

### Purpose
The `janitor_test.go` file ensures the correctness of the background janitor goroutine responsible for cleaning up inactive network tunnels. It validates that stale entries are detected, reported, and removed while fresh ones are preserved.

### Key Components

#### `mockTunnelStore`
A test double implementing the `TunnelStore` interface. It provides thread-safe access to tunnel metadata (`lastSeen` times) using `sync.RWMutex`. It includes stub implementations for peer management methods not relevant to janitor logic.

#### Test Functions

*   **`TestJanitor_SweepsStaleTunnels`**: Verifies that the janitor identifies tunnels with old `lastSeen` timestamps, triggers the cleanup callback, and reports usage. It confirms fresh tunnels (future timestamp) are ignored.
*   **`TestJanitor_StopsGracefully`**: Ensures that calling `Stop()` halts the internal ticker and prevents further sweeps after shutdown.
*   **`TestJanitor_RespectsClosingFlag`**: Confirms that if the closing flag is set to true before or during execution, the janitor skips cleanup operations entirely.