<!-- docdaemon ts:2026-11-12T09:10:30Z hash:f7a7384f9491dd5d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a fan-out proxy that relays HTTP-01 ACME challenge responses from sibling cluster nodes when the current node cannot answer locally.

### Purpose
In a weft cluster with round-robin DNS, CA validators may hit any node. Since only the ordering node holds the key authorization, this module fetches the token from peers to ensure validation succeeds. It avoids 301 redirects because Let's Encrypt rejects them for bare IP addresses.

### Key Components

*   **`FetchChallengeFromPeers`**: The main entry point. It validates the path, resolves peer IPs via `peerCandidates`, and fans out parallel requests to all siblings. It returns the first successful (200) response body and the source IP.
*   **`NoProxyParam`**: A query parameter (`weft-redirect=true`) added to peer requests. This ensures peers answer from their own state without forwarding again, preventing loops.
*   **`peerCandidates`**: Filters DNS records to exclude local IPs, loopback, link-local, and multicast addresses. It caps results at `maxPeers` (16) to limit fan-out.
*   **`fetchFromPeer`**: Performs the actual HTTP GET to a specific peer IP on port 80. It disables redirect following and limits response size to `maxKeyAuthBytes`.

### Configuration & Limits
*   **Timeouts**: `peerFetchTimeout` is set to 5 seconds to stay within Let's Encrypt's ~10s window. Individual dial timeouts are 3 seconds.
*   **Security**: `validToken` enforces RFC 8555 base64url constraints to prevent unnecessary fan-outs for invalid paths.
*   **Logging**: Emits structured events (`acme_challenge_proxied`, `acme_challenge_proxy_missed`, `acme_challenge_peer_failed`) for health monitoring.