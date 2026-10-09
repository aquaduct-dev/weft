<!-- docdaemon ts:2026-10-09T01:40:45Z hash:666a17d4d5b9bef3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the Weft control plane server, handling tunnel lifecycle management, authentication challenges, and WireGuard device orchestration.

### Purpose
The `Server` struct acts as the central coordinator for the control plane. It manages persistent state via a `TunnelStore`, orchestrates network connectivity through a `Dataplane`, and exposes HTTP endpoints for client interaction. It also handles periodic maintenance tasks like usage reporting and stale tunnel cleanup.

### Key Types and Functions

*   **`Server`**: The main struct embedding `http.Server`. It holds configuration (TLS certs, secrets), state (challenges, peers), and background workers (`Janitor`, `UsageReporter`).
*   **`NewServer`**: Constructor that initializes the HTTP mux, generates self-signed TLS certificates, sets up the dataplane, and starts background janitors and reporters. It registers routes for `/login`, `/connect`, `/healthcheck`, etc.
*   **`CreateDevice`**: Utility to initialize a userspace WireGuard device on a specific port, returning the private key and actual listen port.
*   **Authentication**: Implements a challenge-response login flow using `ConnectionSecret` and JWTs. The `/login` endpoint is unauthenticated but issues tokens; other endpoints require valid JWTs via `requireJWT`.
*   **Security**: Generates a SHA-256 fingerprint of the leaf certificate (`certFingerprintHex`) for out-of-band pinning to prevent MITM attacks.

### Integration
This file sits at the core of the application, bridging the HTTP API layer with the underlying networking logic in `wireguard` and `dns` packages. It relies on `crypto` for certificate generation and uses `zerolog` for structured logging.