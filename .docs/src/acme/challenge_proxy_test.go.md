<!-- docdaemon ts:2026-10-29T21:04:47Z hash:61c27782df9939a9 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `FetchChallengeFromPeers` function, verifying its parallel fan-out logic, peer filtering, and proxy prevention mechanisms.

### Purpose
The tests ensure that ACME HTTP-01 challenges are correctly fetched from sibling nodes when the local node lacks the key authorization. This addresses historical issues where round-robin DNS caused Let's Encrypt validators to hit nodes without the challenge data, which previously failed because 301 redirects to bare IPs were rejected by CAs.

### Key Test Scenarios

*   **Successful Fetch (`TestFetchChallengeFromPeers_ReturnsTheOnePeerWithTheToken`)**: Verifies that the function returns the correct body and peer IP when exactly one peer holds the token. It also confirms that:
    *   The local interface is not queried.
    *   All peers receive the request with `NoProxyParam=true`, preventing recursive forwarding loops.
    *   The original `Host` header is preserved.
*   **Failure Modes**:
    *   **No Peer Answered**: Confirms `ErrNoPeerAnswered` is returned if no peer has the token or if all peers return errors (e.g., 403).
    *   **Redirects Ignored**: Ensures the client does not follow HTTP redirects, as this would bypass the peer discovery mechanism.
    *   **Oversized Body**: Rejects responses exceeding `maxKeyAuthBytes` to prevent resource exhaustion.
    *   **Invalid Paths**: Rejects requests that do not match the expected `ChallengePathPrefix` structure.
*   **Network Filtering (`TestFetchChallengeFromPeers_SkipsLoopbackAndLinkLocal`)**: Validates that loopback (127.0.0.1) and link-local (fe80::, 169.254.x.x) addresses are excluded from the peer list to avoid unnecessary internal traffic.
*   **Proxy Detection (`TestIsNoProxyRequest`)**: Unit tests for the helper function that identifies requests already marked with `NoProxyParam=true`.

### Implementation Details
The test suite uses `fakePeers` to spin up mock HTTP servers and swaps out DNS lookups, interface address resolution, and dialing functions via `SwapLookupIPForTest`, `SwapInterfaceAddrsForTest`, and `SwapDialPeerForTest`. This allows precise control over network behavior without external dependencies.