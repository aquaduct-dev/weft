<!-- docdaemon ts:2026-10-19T23:26:06Z hash:3434084acf29be0b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains Ginkgo/Gomega integration tests for the ACME redirect and peer discovery logic.

It verifies `DescendingPeerIPs` sorts IPs by byte order and propagates DNS errors, while `LocalIPs` correctly filters out loopback addresses using stubbed network interfaces. The `IsLocalIP` tests ensure equality checks handle IPv4-mapped IPv6 addresses properly.

`PostACMERedirect` is tested against a TLS test server to confirm it POSTs to `/acme-redirect` with the correct host query parameter, handles 204 responses, and returns errors for 4xx statuses or unreachable peers.

The core logic, `RegisterRedirectsLoop`, is tested via `startPeer` and `runLoop` helpers that inject DNS and interface seams. It validates that the loop skips unreachable higher peers to register with the next available one, declares itself leader when no higher peers are reachable, and respects context cancellation. Log output is captured using a custom `lockedBuffer` and `writerFunc` to assert on events like `EventRedirectTargetChanged`, `EventRedirectPostFailed`, and `EventRedirectLeaderSelf`.