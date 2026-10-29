<!-- docdaemon ts:2026-10-29T21:04:45Z hash:09999104eca3d01d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a fan-out proxy that fetches HTTP-01 challenge responses from sibling cluster nodes when the current node lacks the key authorization.

The ACME protocol requires validating domain control via `/.well-known/acme-challenge/`. In a round-robin DNS setup, validation requests may land on any node, but only the node that initiated the order holds the token. Instead of redirecting (which Let's Encrypt rejects for bare IPs), this module queries all other peers in the DNS set in parallel. It uses the `weft-redirect=true` query parameter to ensure peers answer from local state only, preventing loops.

**Key Components:**
*   **`FetchChallengeFromPeers`**: The main entry point. It validates the path, resolves peer IPs via DNS, and spawns concurrent fetches. It returns the first successful 200 response or an error if no peer has the token.
*   **`fetchFromPeer`**: Handles individual HTTP GETs to a specific peer IP on port 80. It enforces a strict timeout and body size limit (`maxKeyAuthBytes`) to prevent resource exhaustion.
*   **`peerCandidates`**: Filters DNS results to exclude loopback, link-local, and local interface IPs, ensuring requests go only to valid siblings.
*   **Seams**: `lookupIP`, `interfaceAddrs`, and `dialPeer` are variable functions to allow unit testing without real network dependencies.