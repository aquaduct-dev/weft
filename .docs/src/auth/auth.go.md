<!-- docdaemon ts:2026-10-19T23:26:04Z hash:8ba3ae2431ac4c8e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package implements the zero-trust authentication flow, handling challenge-response login, JWT management, and AES-GCM encryption for secure tunnel connections.

### Key Components

*   **`GetToken`**: Executes the challenge-response login against `/login`. It decrypts the server's challenge using the `connectionSecret`, encrypts the response, and retrieves a signed JWT and the server's encrypted certificate.
*   **`Login`**: Orchestrates the full setup by calling `GetToken`, verifying the decrypted server certificate, and returning an `http.Client` configured with automatic JWT refresh via `WithJWT`.
*   **`WithJWT`**: A `http.RoundTripper` wrapper that injects Bearer tokens into requests and automatically refreshes them if they are nearing expiration (less than 1 minute remaining).
*   **`Encrypt` / `Decrypt`**: Helper functions using AES-GCM with keys derived from the connection secret via SHA-256. Used to secure the challenge exchange and the server certificate payload.
*   **`PinnedFingerprint`**: An optional global variable for out-of-band TLS pinning during the initial handshake to prevent MITM attacks before certificate verification is established.

### Integration
This file was extracted from `cmd/tunnel.go` to separate CLI orchestration from cryptographic logic. It relies on `src/version` to annotate login errors with client/server version mismatches, aiding in debugging connectivity issues.