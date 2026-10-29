<!-- docdaemon ts:2026-10-29T21:04:49Z hash:2dd9cb479346f796 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines a `testDataplane` struct that implements the server's dataplane interface to provide a lightweight, no-op implementation for unit tests.

The `testDataplane` type satisfies the `Dataplane` interface by returning zero values or empty collections for all methods. It is designed for handler tests that do not need to exercise WireGuard configuration, proxy plumbing, or certificate management logic.

Key components include:
*   **State Tracking**: The struct holds `counters` (a map of `ProxyCounters`) and `acmeFailures` (a slice of `types.ACMEFailure`). These fields allow tests to verify side effects like counter increments or ACME failure reporting without invoking real network operations.
*   **No-Op Methods**: Methods such as `UpdateWireGuardConfig`, `StartProxy`, and `CloseProxy` return immediately with nil errors or default values. This isolates the test subject from infrastructure dependencies.
*   **ACME Failure Reporting**: The `ListACMEFailures` method returns the stored failures, supporting tests that verify how the server reports background issuance errors (e.g., after commits addressing challenge validation and error logging).

By using this stub, tests can focus on HTTP handler logic and state transitions while ignoring the complexity of the underlying proxy and certificate acquisition systems.