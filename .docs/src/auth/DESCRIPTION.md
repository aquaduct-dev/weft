<!-- docdaemon ts:2026-10-19T23:27:09Z hash:784c67270870838e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `auth` package implements zero-trust authentication, handling challenge-response login, JWT lifecycle management, and AES-GCM encryption for secure tunnel connections.

## Overview
This module orchestrates the initial handshake between the client and server, ensuring that only authorized clients can establish encrypted tunnels. It manages the exchange of cryptographic challenges, validates server certificates to prevent man-in-the-middle attacks, and maintains valid JSON Web Tokens (JWTs) for subsequent API requests. By separating cryptographic logic from CLI orchestration, it provides a reusable library for secure connectivity.

## Deep Dive
### Challenge-Response Login
Authentication begins with `GetToken`, which performs a challenge-response exchange against `/login`. The client decrypts a server-provided challenge using a shared connection secret, encrypts the response, and retrieves a signed JWT along with an encrypted server certificate. This ensures that only parties possessing the secret can complete the handshake.

### Certificate Verification
To mitigate MITM risks during the initial TLS handshake, the package supports optional out-of-band TLS pinning via `PinnedFingerprint`. If set, the client verifies the server's leaf certificate SHA-256 hash before proceeding. Additionally, the server's certificate is returned encrypted in the login response, allowing the client to verify its authenticity after decryption using the connection secret.

### JWT Transport Management
The `WithJWT` function wraps `http.RoundTripper` to inject Bearer tokens into outgoing requests. It includes automatic refresh logic: if a token has less than one minute remaining, it triggers a re-authentication. Robust error handling ensures that malformed tokens or parse failures force a refresh rather than crashing the process, maintaining stability in the hot path.

### Cryptographic Helpers
Utility functions `Encrypt` and `Decrypt` use AES-GCM with keys derived from the connection secret via SHA-256. These secure the challenge exchange and certificate payload, ensuring confidentiality and integrity of sensitive data during transmission.

## Key Interfaces
- `GetToken`: Executes the challenge-response login and returns a JWT and encrypted certificate.
- `Login`: Orchestrates full setup, verifying certificates and returning an authenticated `http.Client`.
- `WithJWT`: An `http.RoundTripper` wrapper for automatic Bearer token injection and renewal.
- `PinnedFingerprint`: Global variable for optional TLS pinning during initial handshake.
- `Encrypt` / `Decrypt`: Helper functions for AES-GCM encryption/decryption using derived keys.

## Dependencies
- `//src/version`: Provides client/server version information for debugging mismatches.
- `@com_github_golang_jwt_jwt_v4//:jwt`: Handles JWT parsing, validation, and claim extraction.
- `@com_github_rs_zerolog//log`: Provides structured logging for authentication events and errors.

## Subcomponents
- `auth.go`: Core authentication logic, crypto helpers, and HTTP transport wrapper.
- `auth_test.go`: Unit tests for JWT expiry handling, version annotation, and transport behavior.
- `fingerprint_test.go`: Tests for TLS fingerprint pinning and certificate verification.
- `BUILD.bazel`: Bazel build rules defining the library and test targets.