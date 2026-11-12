<!-- docdaemon ts:2026-11-12T09:40:23Z hash:e2d0dc68e52001be model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides ACME certificate acquisition helpers with structured logging and rate-limit handling for the server's TLS setup.

### Purpose
The package wraps `autocert.Manager` to manage certificate lifecycle, ensuring HTTPS listeners wait for valid certificates while providing detailed observability into issuance attempts. It specifically addresses CA rate limits by holding requests locally until the CA allows retry, preventing cascading failures.

### Key Components

*   **`ACMEHelper`**: A wrapper struct around `*autocert.Manager`. Its primary method, `WaitForCertificate`, blocks until a certificate is available or the context expires, used during server startup.
*   **`AcquireCertificate`**: The core logic for fetching certificates via `GetCertificate`. It distinguishes between cache hits and fresh issuances, emitting structured log events (`acme_cache_hit`, `acme_issuance_started`, etc.) for audit trails.
*   **Rate Limit Handling**: The package tracks CA-imposed rate limits per host. If a request fails due to rate limiting, subsequent requests for that host are served from local state (or blocked) until the CA-specified `Retry-After` time elapses. This prevents extending the wait period caused by repeated failed attempts.

### Usage
Use `NewACMEHelper` to wrap your configured manager. Call `WaitForCertificate` before mounting HTTPS listeners to ensure the certificate is ready. For runtime TLS handshakes, use `AcquireCertificate` directly if you need the detailed logging and rate-limit protection provided by this wrapper.