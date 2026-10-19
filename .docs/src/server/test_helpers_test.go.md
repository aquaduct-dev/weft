<!-- docdaemon ts:2026-10-19T23:25:57Z hash:23c8ced17c1439e1 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a minimal `testDataplane` stub to isolate handler logic from WireGuard and proxy infrastructure during unit testing.

The `testDataplane` struct implements the `Dataplane` interface, allowing tests to verify HTTP handlers without spinning up real network listeners or ACME clients. It maintains in-memory maps for `ProxyCounters` and `ACMEFailures`, enabling assertions on state changes triggered by requests.

Key behaviors include:
- **Stubbed Networking**: Methods like `StartProxy`, `CloseProxy`, and `UpdateWireGuardConfig` return immediately with no-op results, preventing side effects.
- **ACME State Tracking**: `ListACMEFailures` returns stored failures, supporting tests that verify error reporting (e.g., after background issuance fails).
- **Certificate Listing**: `ListCertificates` returns an empty slice, sufficient for tests checking endpoint structure rather than actual cert content.

This fixture ensures handler tests remain fast and deterministic by decoupling them from external dependencies.