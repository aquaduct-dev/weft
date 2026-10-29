<!-- docdaemon ts:2026-10-29T21:04:45Z hash:9d9fe91df9a99586 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides exported test seams to mock DNS resolution, local network interfaces, and peer dialing for the ACME challenge proxy.

These helpers allow cross-package tests (e.g., in `src/proxy/vhost`) to inject deterministic state without affecting production behavior. They replace package-level function variables (`lookupIP`, `interfaceAddrs`, `dialPeer`) with closures that return controlled data.

### Key Functions

*   **`SwapLookupIPForTest`**: Replaces `net.LookupIP` with a map of hostnames to IP addresses. Unparseable IPs are silently skipped. Returns the previous function for restoration.
*   **`RestoreLookupIPForTest`**: Restores the original DNS lookup function.
*   **`SwapInterfaceAddrsForTest`**: Mocks local interface addresses by converting dotted-decimal strings into `net.IPNet` objects. Invalid entries are ignored.
*   **`RestoreInterfaceAddrsForTest`**: Restores the original interface address retrieval.
*   **`SwapDialPeerForTest`**: Replaces the peer dialing logic with a custom function accepting context and IP. This is critical for testing peer-to-peer challenge routing where validators may land on different nodes.
*   **`RestoreDialPeerForTest`**: Restores the original dialing function.

### Usage Notes
All functions are exported solely for testing purposes. Production code must never call these. Always restore the previous seam function after tests complete to prevent state leakage between test cases.