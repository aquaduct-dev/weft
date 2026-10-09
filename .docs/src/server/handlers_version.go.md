<!-- docdaemon ts:2026-10-09T01:40:39Z hash:1d856729f0a248f4 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the HTTP handler that exposes build metadata for client-side version verification.

### Purpose
The `VersionHandler` provides a lightweight, unauthenticated endpoint to report the current server’s commit hash and build date. This allows clients to detect version mismatches during login handshakes without exposing any sensitive credentials or secrets.

### Key Components
- **`VersionHandler`**: An HTTP handler method on the `Server` struct. It sets the response content type to JSON and encodes a map containing `commit` and `date` fields sourced from the `version` package.
- **Security**: The endpoint is intentionally public and carries no secrets, making it safe for unauthenticated access.

### Integration
This handler is part of the `server` package and relies on the `github.com/aquaduct-dev/weft/src/version` package for static build information. It fits into the broader server architecture as a diagnostic tool for client-server compatibility checks.