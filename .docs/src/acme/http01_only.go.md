<!-- docdaemon ts:2026-11-01T18:05:29Z hash:295c3753ab845f94 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides an HTTP transport wrapper that forces the ACME client to use only the HTTP-01 challenge by stripping TLS-ALPN-01 from server responses.

### Purpose
In round-robin DNS environments, `autocert` fails on `tls-alpn-01` because only the node placing the order holds the challenge certificate. This causes repeated authorization failures, hitting rate limits before `http-01` can succeed. This package intercepts ACME responses to remove `tls-alpn-01`, ensuring immediate fallback to `http-01`.

### Key Components

*   **`HTTP01OnlyTransport`**: Wraps a standard `http.RoundTripper`. It intercepts successful JSON responses and filters out `tls-alpn-01` challenges using `dropTLSALPN01`.
*   **`NewHTTP01OnlyClient`**: Returns an `acme.Client` configured with the custom transport and the default ACME directory. Use this for `autocert.Manager.Client`.
*   **`dropTLSALPN01`**: Parses the response body as JSON, removes any challenge objects where `type` is `tls-alpn-01`, and re-marshals the object. If no such challenges exist or parsing fails, it returns the original body unchanged.

### Behavior
The transport reads the full response body (capped at 1MB) into memory. If the content type is JSON and filtering occurs, it replaces the response body with the filtered version and updates `Content-Length`. This ensures `autocert` sees only valid `http-01` authorizations.