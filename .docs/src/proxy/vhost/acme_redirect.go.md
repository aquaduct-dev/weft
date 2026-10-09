<!-- docdaemon ts:2026-10-09T01:40:27Z hash:f54b63883aedf10c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file coordinates HTTP-01 ACME challenge redirection among cluster peers to ensure certificate issuance succeeds regardless of which node receives the DNS query.

### Purpose
The `acme_redirect` module manages a leader-fallback strategy for Let's Encrypt validation. It allows a peer to register its IP as the authoritative responder for a specific host, while providing a deterministic fallback to the highest-IP node in DNS if no registration exists. This prevents race conditions and split-brain scenarios during certificate renewal.

### Key Components

*   **`peerRedirect`**: A struct holding the target `peerIP` and an expiration timestamp. Entries auto-expire after `peerRedirectTTL` (5 minutes) to handle transient network partitions gracefully.
*   **`RegisterPeerRedirect`**: Called by the control plane (`/acme-redirect` endpoint) after validating that the requesting IP is associated with the host in DNS. It stores the redirect target in the manager's map.
*   **`lookupPeerRedirect`**: Thread-safe lookup that returns the registered peer IP if the entry is valid, or deletes expired entries.
*   **`tryRedirectChallenge`**: The core logic invoked by the `/.well-known/acme-challenge/*` handler. It executes the following priority chain:
    1.  **Registered Peer**: If a valid peer registration exists, 301 redirects to that peer.
    2.  **Local Host**: If the host is managed locally (`acmeHosts`), it falls through to `autocert` to serve the key directly.
    3.  **Highest-IP Fallback**: If no peer is registered, it resolves DNS for the host. If the highest-IP entry is not local, it 301 redirects there. If the local node *is* the highest IP, it falls through to `autocert`.