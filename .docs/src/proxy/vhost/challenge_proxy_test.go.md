<!-- docdaemon ts:2026-10-30T02:43:10Z hash:b0e4f1314ce789bd model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
End-to-end tests verifying that ACME HTTP-01 challenges are correctly proxied among cluster nodes without redirect loops or excessive hops.

### Purpose
Validates `serveChallenge` behavior in a multi-node setup where round-robin DNS distributes validation requests across peers, but only one node holds the specific token. Ensures nodes forward requests to peers when necessary, while strictly limiting forwarding to a single hop to prevent infinite loops.

### Key Components
*   **`testNode`**: Wraps a `VHostProxyManager` and an `httptest.Server` to simulate individual bastion nodes with distinct IPs.
*   **`newRRCluster`**: Spins up a cluster of nodes sharing a hostname (`rr.example.com`). It swaps out `acme` package lookups and dialers to route traffic between fake IPs within the same process.
*   **`writeToken`**: Manually places key authorization files into the node's certificate cache directory to simulate an order in flight.

### Test Scenarios
*   **`TestServeChallenge_EveryNodeAnswersForTheOrderer`**: Confirms that any node can answer for a token held by another, and verifies that no request is forwarded more than once (single-hop proxying).
*   **`TestServeChallenge_SeveralOrdersInFlight`**: Tests concurrent orders where each node holds a unique token, ensuring isolation and correct routing for all active challenges.
*   **`TestServeChallenge_UnknownTokenIs404Everywhere`**: Verifies that unknown tokens return 404s from every node, preventing information leakage about which node might hold a valid token.
*   **`TestServeChallenge_NoProxyRequestIsAnsweredLocally`**: Ensures requests marked with `NoProxyParam` are not forwarded, forcing local resolution or failure.