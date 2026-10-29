<!-- docdaemon ts:2026-10-29T21:04:45Z hash:b264f33d5043d508 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a distributed HTTP-01 challenge proxy that allows multiple nodes sharing a hostname to collaboratively satisfy ACME certificate validation requests.

### Purpose
In round-robin DNS setups, CA validators may hit any node in the cluster. Since only the node that initiated the order holds the key authorization, this handler ensures challenges are answered correctly regardless of which node receives the request. It attempts a local lookup first, then fans out to peers if necessary, preventing redirect loops and ensuring valid responses.

### Key Components

*   **`bufferedResponse`**: A custom `http.ResponseWriter` implementation that captures headers, status codes, and body content. This allows the system to inspect the result of a local ACME handler before deciding whether to serve it or relay a peer's response.
*   **`serveChallenge`**: The main entry point for handling requests under `/.well-known/acme-challenge/`.
    *   **No-Proxy Guard**: If the request carries `acme.NoProxyParam` (indicating it was forwarded by another node), it serves locally only. This prevents infinite fan-out loops.
    *   **Local Check**: It queries the local autocert manager. If a 200 OK is found, it writes the response immediately.
    *   **Peer Relay**: If the local state lacks the token, it calls `acme.FetchChallengeFromPeers` to query other nodes in the host's DNS set. It returns the first successful (200) response received from a peer.
    *   **Fallback**: If no peer answers, it returns its own local response (typically 404 or 403).