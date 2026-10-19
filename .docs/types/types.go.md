<!-- docdaemon ts:2026-10-19T23:26:02Z hash:51efc545207d4202 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the shared data structures for API requests, responses, and internal state used by the tunnel proxy server.

### API Payloads
*   **ConnectRequest**: Defines parameters for establishing a tunnel, including routing rules (`RemotePath`, `RemoteQuery`), request modifiers (header manipulation, redirects), and optional TLS termination credentials (`CertificatePEM`, `PrivateKeyPEM`). The `TunnelName` defaults to a hash if omitted.
*   **ConnectResponse**: Returns server-side connection details, including the WireGuard port and assigned proxy port.
*   **HealthcheckRequest/Response**: Simple diagnostic endpoints where the server echoes back the client's message field.

### Certificate Management
*   **CertificatesResponse**: Aggregates cached TLS certificate metadata (`CertInfo`) and recent ACME issuance failures (`ACMEFailure`). This supports the `/certificates` endpoint, allowing operators to monitor cert validity and debug background issuance errors.

### Telemetry
*   **UsageReport/TunnelUsage**: Tracks per-tunnel byte transfer statistics (`BytesTx`, `BytesRx`) for reporting purposes.