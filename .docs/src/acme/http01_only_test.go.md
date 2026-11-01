<!-- docdaemon ts:2026-11-01T18:05:30Z hash:9d833d052d618893 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `HTTP01OnlyTransport` HTTP transport and `NewHTTP01OnlyClient` helper, ensuring ACME authorizations exclude `tls-alpn-01` challenges.

The `HTTP01OnlyTransport` is designed to filter out `tls-alpn-01` challenge types from ACME responses. This behavior addresses a specific failure mode in round-robin DNS environments: when multiple nodes share a hostname, only the node that placed the order holds the necessary TLS certificate for `tls-alpn-01`. Other nodes fail validation, quickly hitting Let's Encrypt's rate limit of 5 failed authorizations per hour. By stripping this challenge type, the client forces the use of `http-01`, which works reliably across all nodes in the rotation.

### Key Components

*   **`TestHTTP01OnlyTransport_RemovesTLSALPN01`**: Verifies that an authorization containing `http-01`, `dns-01`, and `tls-alpn-01` challenges is filtered to contain only `http-01` and `dns-01`. It also ensures that other fields (status, identifier) and headers (Replay-Nonce) remain intact.
*   **`TestHTTP01OnlyTransport_PassesOtherResponsesThrough`**: Confirms that non-challenge responses (orders, certificate chains, error documents) and JSON bodies without challenges are passed through unmodified.
*   **`TestNewHTTP01OnlyClient_LeavesKeyForAutocert`**: Ensures the created client has a `nil` key, allowing `autocert` to load the cached account key instead of generating a new one.