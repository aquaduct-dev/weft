<!-- docdaemon ts:2026-10-09T01:41:03Z hash:c65d8313e94f91a3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script performs an end-to-end test of the HTTPS tunneling capability by establishing a secure connection between a local HTTP server and a remote endpoint.

### Purpose
The file validates that `weft` can successfully tunnel traffic while presenting TLS on the remote side, using self-signed certificates for isolation from external dependencies.

### Key Components
- **Certificate Generation**: Creates a temporary RSA 2048-bit self-signed certificate (`cert.pem`) and key (`key.pem`) valid for one day.
- **Local Server**: Spawns a Python `http.server` instance to provide a static response payload.
- **Weft Infrastructure**: Starts the `weft` server to generate a connection secret, then launches the tunnel agent. The tunnel is configured with `--tls-cert` and `--tls-key` flags to enforce HTTPS on the remote listener.
- **Verification**: Polls the remote port until reachable, then uses `curl -k` (insecure) to verify the response body matches the expected string.

### Integration
This test is self-contained and does not rely on `test_tcp_tunnel.sh`. It exports environment variables for cert paths if supported by the tunnel implementation and cleans up all temporary files and processes upon exit via a trap.