<!-- docdaemon ts:2026-10-30T02:43:09Z hash:4789f7b4daecb602 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a distributed HTTP-01 challenge proxy that allows multiple nodes sharing a hostname to collaboratively satisfy ACME certificate issuance requests.

The `bufferedResponse` type captures the local autocert handler's response, enabling the system to decide whether to serve it directly or relay a peer's answer. The core logic resides in `serveChallenge`, which first attempts to answer locally. If the local node lacks the token (non-200 status), it queries sibling nodes via `acme.FetchChallengeFromPeers`.

To prevent infinite fan-out loops, requests forwarded by peers carry the `acme.NoProxyParam` marker; these are answered locally only and never re-forwarded. If no peer has the token, the request falls through to the backend if `canFallThrough` is true, allowing user-managed ACME clients to complete their own challenges. This design replaces previous 301 redirects, which failed with Let's Encrypt when validators hit random nodes in round-robin DNS setups.