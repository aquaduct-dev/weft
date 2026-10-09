<!-- docdaemon ts:2026-10-09T01:40:46Z hash:05e24a4c3b648ea6 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a minimal `testDataplane` stub to facilitate unit testing of server handlers without requiring live WireGuard or proxy infrastructure.

### Purpose
The `testDataplane` struct implements the `Dataplane` interface with no-op methods, allowing tests to isolate handler logic from external dependencies like network configuration and certificate management.

### Key Components
- **`testDataplane`**: A lightweight struct holding an internal `counters` map for tracking proxy statistics during tests.
- **`newTestDataplane()`**: Constructor that initializes the counters map.
- **Stubbed Methods**: All interface methods (`UpdateWireGuardConfig`, `StartProxy`, `CloseProxy`, etc.) return zero values or nil errors, ensuring they do not interfere with test assertions.
- **Counter Tracking**: `GetProxyCounters` returns the internal map, enabling verification of proxy activity within the tested scope.