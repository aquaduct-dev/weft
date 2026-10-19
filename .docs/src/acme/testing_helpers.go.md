<!-- docdaemon ts:2026-10-19T23:26:03Z hash:f1405efde286e116 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides exported test seams to inject deterministic DNS and network interface state for cross-package testing.

### Purpose
These helpers allow tests in other packages (e.g., `src/proxy/vhost`) to control the behavior of `net.LookupIP` and local interface addresses without modifying production code. They are strictly for testing and must not be called in non-test contexts.

### Key Functions

*   **SwapLookupIPForTest**: Replaces the package-level `lookupIP` function with a closure that returns mapped IPs for specified hosts. Unparseable IP strings are silently skipped. Returns the previous function for restoration.
*   **RestoreLookupIPForTest**: Restores the original `lookupIP` function returned by `SwapLookupIPForTest`.
*   **SwapInterfaceAddrsForTest**: Replaces the `interfaceAddrs` seam to return a fixed list of local IP addresses as `net.IPNet` objects. Invalid IPs are ignored. Returns the previous function.
*   **RestoreInterfaceAddrsForTest**: Restores the original `interfaceAddrs` function.

### Design Notes
The seams support peer fallback and leader election logic by allowing tests to simulate specific network states, such as unreachable peers or specific local bindings. This enables deterministic verification of ACME redirect coordination without relying on real network conditions.