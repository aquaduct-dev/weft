<!-- docdaemon ts:2026-10-09T01:40:28Z hash:7cf792c99bf6971f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides end-to-end integration tests for `MeteredServer.ServeTLSCounted` to verify HTTP/2 negotiation, HTTP/1.1 fallback, ACME TLS-ALPN-01 support, and byte metering accuracy.

### Purpose
The test suite ensures that enabling HTTP/2 does not regress existing functionality. It validates the three critical behaviors of the TLS counting server: protocol negotiation (h2 vs h1), ACME challenge compatibility, and accurate request/response byte accounting.

### Key Components

*   **`TestServeTLSCountes_NegotiatesHTTP2_KeepsH1_ACME_AndMeters`**: The primary test function. It spins up a real TCP listener with a self-signed certificate and runs four verification blocks:
    1.  **HTTP/2**: Confirms that clients offering `h2` receive an HTTP/2 response.
    2.  **HTTP/1.1**: Confirms that clients offering only `http/1.1` are served correctly as a fallback.
    3.  **ACME TLS-ALPN-01**: Verifies that the `acme-tls/1` ALPN protocol is selectable during the TLS handshake, which is required for Let's Encrypt domain validation.
    4.  **Metering**: Checks that `handler.BytesTotal()` reflects non-zero bytes after the requests above.

*   **`selfSignedCert`**: Generates an in-memory X.509 certificate and ECDSA key pair valid for `localhost` and `127.0.0.1`. This avoids filesystem dependencies during testing.

*   **`doGet`**: Helper to issue HTTPS GET requests using a custom `http.Transport` with specific `NextProtos` settings. The `forceH2` flag enables `ForceAttemptHTTP2` on the transport.

*   **`waitReady`**: Polls the server address via TLS dial until a handshake succeeds or a timeout occurs, ensuring the server is listening before tests begin.