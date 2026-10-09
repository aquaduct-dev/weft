<!-- docdaemon ts:2026-10-09T01:40:12Z hash:21c966bbed7b1acb model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package implements a challenge-response authentication flow with AES-GCM encryption to obtain and manage JWT tokens for secure tunnel connections.

## Purpose
Extracted from `cmd/tunnel.go`, this file handles the zero-trust login sequence, including TLS fingerprint pinning, certificate exchange, and automatic JWT renewal. It ensures that only clients possessing the correct connection secret can authenticate with the server.

## Key Components

### Authentication Flow
- **`GetToken`**: Executes the core login logic. It fetches an encrypted challenge, decrypts it using the `connectionSecret`, encrypts the response, and retrieves a signed JWT and the server's certificate.
- **`Login`**: Orchestrates the full setup by calling `GetToken`, verifying the server certificate against a custom pool, and returning an `http.Client` configured with automatic token refresh.
- **`WithJWT`**: Wraps an `http.RoundTripper` to inject Bearer tokens into requests. It automatically detects expiring tokens (within 1 minute) and triggers a refresh via the provided callback.

### Cryptography
- **`Encrypt` / `Decrypt`**: Helper functions using AES-GCM. The key is derived by hashing the `connectionSecret` with SHA-256. Nonces are randomly generated for encryption and prepended to ciphertext.
- **`PinnedFingerprint`**: An optional global variable for out-of-band TLS certificate verification during the initial handshake.

### Utilities
- **`fingerprintVerifier`**: A TLS hook that validates the server's leaf certificate hash against `PinnedFingerprint`.
- **`annotateWithVersions`**: Enhances error messages with client and server version details to aid debugging version mismatches.