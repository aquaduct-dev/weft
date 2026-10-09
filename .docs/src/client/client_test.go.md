<!-- docdaemon ts:2026-10-09T01:40:14Z hash:4db958a68877e69e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains integration tests for the `client` package, verifying tunnel lifecycle and authentication against a mock server.

The test suite uses `httptest.NewTLSServer` to simulate the Weft backend, ensuring the client correctly handles TLS connections, JWT-based authentication, and challenge-response login flows. The `mockServer` struct manages in-memory state for tunnels and challenges, mimicking the real server's `/login`, `/list`, and `/shutdown` endpoints.

Key test functions include:
- **`TestListTunnels`**: Verifies that the client can retrieve active tunnel information.
- **`TestShutdown`**: Ensures the client can successfully terminate a specific tunnel.
- **`TestShutdownUnauthorized`** & **`TestListTunnelsUnauthorized`**: Confirm that invalid credentials result in authentication errors.

These tests validate the end-to-end interaction between the client library and the server API, focusing on security (JWT validation) and operational correctness.