<!-- docdaemon ts:2026-10-19T23:26:06Z hash:ed8e269fe14046dc model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains integration tests for the `client` package, verifying tunnel management and authentication flows against a mock server.

The test suite uses `httptest.NewTLSServer` to simulate the Weft backend, ensuring the client handles TLS correctly. The `mockServer` struct manages in-memory state for tunnels and JWT challenges, replicating the login handshake (challenge-response) and token issuance logic found in the production server.

Key test functions include:
- `TestListTunnels`: Verifies that the client can retrieve active tunnel information using a valid JWT.
- `TestShutdown`: Confirms that the client sends a shutdown request for a specific tunnel and that the server removes it from its registry.
- `TestShutdownNoTunnelName`: Ensures the client rejects shutdown attempts when no tunnel name is specified, preventing accidental global shutdowns.
- `TestShutdownUnauthorized` / `TestListTunnelsUnauthorized`: Validate that requests with invalid secrets are rejected by the server's JWT middleware.

The mock server encrypts certificates and challenges using the shared secret, mirroring the MITM protection mechanism implemented in the actual service.