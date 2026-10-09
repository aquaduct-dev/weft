<!-- docdaemon ts:2026-10-09T01:40:35Z hash:77583a3a8dd30153 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the HTTP handler for listing cached TLS certificates and their validity windows.

### Purpose
The `CertificatesHandler` exposes an endpoint to retrieve the bastion’s currently cached TLS certificates. It allows administrators to inspect which hosts have associated certificates and monitor their expiration dates via a JSON response.

### Key Components
- **`(*Server).CertificatesHandler`**: The primary HTTP handler function. It validates that the request method is `GET`, retrieves the certificate list from the data plane, and encodes the result as JSON using `types.CertificatesResponse`.

### Integration
This handler is registered in the server mux (see `server.go`) and requires JWT authentication, consistent with other admin endpoints. It relies on `s.Dataplane.ListCertificates()` to fetch the underlying data.