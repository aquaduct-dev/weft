<!-- docdaemon ts:2026-10-09T01:40:37Z hash:a95c00efd0c31668 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the multi-step challenge-response authentication flow for proxy connections, issuing login challenges and validating them to issue signed JWTs.

### Purpose
The `handlers_auth.go` module manages the initial handshake between a client (proxy) and the server. It prevents unauthenticated resource exhaustion by limiting outstanding challenges and ensures secure token issuance using HMAC-SHA256.

### Key Components

*   **`challengeEntry`**: Tracks the value and expiration time of a single login challenge.
*   **`LoginHandler`**: Dispatches GET requests to generate challenges and POST requests to verify them.
*   **`getChallenge`**: Generates a cryptographically random hex string, stores it in `Server.challenges` (bounded by `maxOutstandingChallenges`), and returns an encrypted version.
*   **`verifyChallenge`**: Consumes the stored challenge, decrypts the client's response, and validates it using constant-time comparison. On success, it issues a JWT with `iss`, `iat`, `nbf`, `exp`, and `sub` claims, along with an encrypted TLS certificate.
*   **`ValidateJWT`**: Parses and validates incoming JWTs. It verifies the signature against `ConnectionSecret`, checks that the issuer is "weft", and rejects tokens with an `iat` more than 5 minutes in the future.

### Integration
This handler interacts with `crypto.Encrypt`/`Decrypt` for data protection and relies on `Server.ConnectionSecret` for signing keys. The `s.challenges` map is protected by `s.mu` to ensure thread-safe access during sweep operations.