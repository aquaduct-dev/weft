<!-- docdaemon ts:2026-10-19T23:26:06Z hash:4b6af11ccd924688 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the JWT authentication transport and version mismatch error handling.

It verifies that `WithJWT` correctly triggers token renewal when a token is near expiry, updates internal state, and avoids redundant renewals for valid tokens. The `TestJwtExpiry` function ensures robust parsing of expiration times, preventing panics on malformed or missing claims by centralizing logic in `jwtExpiry`.

Tests for `annotateWithVersions` confirm that login errors are enriched with client and server version information. It validates three scenarios: clear version mismatches, matching versions, and unreachable servers, ensuring the original error remains unwrapable via `errors.Is`.