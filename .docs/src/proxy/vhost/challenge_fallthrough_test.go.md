<!-- docdaemon ts:2026-10-30T02:43:09Z hash:f4c4ae0f08b03f96 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file tests that ACME HTTP-01 challenges for hosts managed by external clients are correctly routed to the backend instead of being intercepted by weft.

The `userBackend` helper simulates an external ACME client running behind a tunnel, recording requests and serving specific challenge tokens. The `newPlainNode` function configures a `VHostProxyManager` with a dedicated challenge port and optional plain-HTTP routes to the backend.

Tests verify three key behaviors:
1. **Direct Fall-through**: Challenges for unmanaged hosts reach the backend directly.
2. **Peer Relay**: When a sibling bastion receives a challenge it cannot serve locally, it relays the request to the correct peer, preserving the backend's response.
3. **Interception Logic**: Weft correctly intercepts challenges for hosts it manages (returning 404 if not configured) or blocks them (403) if no route exists.

The `noPeers` helper isolates local behavior by disabling DNS lookups, ensuring tests do not depend on network topology unless explicitly simulated (as in `TestChallengeFallThrough_SiblingRelaysUserBackend`).