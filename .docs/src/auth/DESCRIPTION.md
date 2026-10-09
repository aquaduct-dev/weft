<!-- docdaemon ts:2026-10-09T01:42:03Z hash:0b86cd881dc0f37c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `auth` package implements a zero-trust challenge-response authentication flow using AES-GCM encryption and JWT management for secure tunnel connections.

## Overview
This directory handles the critical security handshake required to establish trusted tunnels between clients and servers. It extracts complex login logic from the main command entry point to ensure modularity and testability. The system relies on TLS fingerprint pinning and shared connection secrets to verify identity without traditional password storage. By automating JWT renewal and certificate verification, it maintains persistent, secure sessions with minimal developer overhead.

## Deep Dive
### Authentication Flow
The core logic resides in `GetToken` and `Login`. `GetToken` performs the cryptographic exchange: it decrypts a server challenge using a SHA-256 derived key from the `connectionSecret`, encrypts the response, and retrieves a signed JWT alongside the server's certificate. `Login` orchestrates this by verifying the server certificate against a custom pool (optionally pinned via `PinnedFingerprint`) and returning an `http.Client` configured for automatic token refresh.

### Cryptography and Security
Security is enforced through AES-GCM encryption for all challenge-response payloads. Nonces are randomly generated and prepended to ciphertexts to prevent replay attacks. The `fingerprintVerifier` acts as a TLS hook, validating the server's leaf certificate hash against a pre-shared value (`PinnedFingerprint`). If no pin is set, the system falls back to standard verification or insecure modes depending on configuration, though pinning is recommended for production.

### Token Management
The `WithJWT` middleware wraps `http.RoundTripper` implementations to inject Bearer tokens into outgoing requests. It proactively detects tokens expiring within one minute and triggers a refresh callback before the request fails. This ensures seamless session continuity without manual intervention. Error messages are annotated with client and server version details via `annotateWithVersions` to simplify debugging version mismatches during the handshake.

## Key Interfaces
- `GetToken`: Executes the challenge-response login sequence and returns a JWT and server certificate.
- `Login`: Orchestrates full setup, verifies certificates, and returns an authenticated `http.Client`.
- `WithJWT`: Middleware that injects Bearer tokens and handles automatic renewal for expiring tokens.
- `Encrypt` / `Decrypt`: Helper functions performing AES-GCM encryption/decryption using SHA-256 derived keys.
- `PinnedFingerprint`: Global variable storing the expected SHA-256 hash of the server's leaf certificate.

## Dependencies
- `//src/version`: Provides versioning information for error annotation and compatibility checks.
- `@com_github_golang_jwt_jwt_v4//:jwt`: Handles JWT parsing, validation, and signing.
- `@com_github_rs_zerolog//log`: Provides structured logging for authentication events and errors.

## Subcomponents
- `BUILD.bazel`: Defines build rules for the Go library and its tests.
- `auth.go`: Core implementation of authentication, cryptography, and HTTP middleware.
- `auth_test.go`: Unit tests for JWT renewal logic and version-aware error handling.
- `fingerprint_test.go`: Unit tests for TLS certificate pinning and verification.