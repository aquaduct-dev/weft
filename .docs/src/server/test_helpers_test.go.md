<!-- docdaemon ts:2026-10-30T02:43:13Z hash:7133964f66ca3679 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines a `testDataplane` struct that implements the server's dataplane interface to provide a lightweight, no-op mock for unit testing handlers without requiring real WireGuard or proxy infrastructure.

The `testDataplane` type satisfies the `Dataplane` interface by returning empty or zero-value results for all operations. It maintains internal state for `counters` and `acmeFailures` to allow tests to verify metrics and ACME error reporting logic. Methods like `UpdateWireGuardConfig`, `StartProxy`, and `CloseProxy` are stubbed to return immediately, ensuring that handler tests focus on HTTP routing and response generation rather than network side effects.

Key methods include:
- **`GetProxyCounters`**: Returns the current map of proxy counters, allowing assertions on traffic metrics.
- **`ListACMEFailures`**: Returns stored ACME failures, enabling verification of how the system reports issuance errors (e.g., after background goroutine failures).
- **`SetACMEEmail` / `SetCertsCachePath`**: No-op setters that satisfy interface requirements but do not persist configuration in tests.

This mock is used exclusively within `*_test.go` files to isolate handler logic from external dependencies.