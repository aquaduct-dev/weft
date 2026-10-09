<!-- docdaemon ts:2026-10-09T01:40:13Z hash:a4a16f62352503c7 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the JWT transport renewal logic and version-aware error annotation in the `auth` package.

### Purpose
The tests verify that HTTP requests are automatically retried with refreshed tokens when nearing expiration, and that login errors are enriched with server version information to aid debugging.

### Key Components

*   **`MockRoundTripper`**: A test helper implementing `http.RoundTripper` to capture the last outgoing request for inspection.
*   **`generateToken`**: Helper to create short-lived JWTs for simulating token expiry scenarios.
*   **`TestWithJwt_Renewal`**: Validates that `WithJWT` triggers the renewal callback exactly once when a token is close to expiring, updates the internal state, and does not renew on subsequent immediate calls.
*   **`startVersionServer`**: Spins up an in-memory TLS server to simulate a backend service for version checking.
*   **`TestAnnotateWithVersions_*`**: Tests the `annotateWithVersions` function (defined elsewhere) to ensure it correctly:
    *   Reports "version mismatch" when client and server commits differ.
    *   Reports "both at version" when they match.
    *   Handles unreachable servers gracefully without panicking.