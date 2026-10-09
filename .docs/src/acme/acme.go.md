<!-- docdaemon ts:2026-10-09T01:40:09Z hash:b1ec75e3e2624d43 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides ACME helper utilities to manage certificate acquisition and caching via `autocert.Manager`.

### Purpose
The package wraps `golang.org/x/crypto/acme/autocert` to simplify HTTPS listener setup. It ensures certificates are available before mounting listeners and emits structured logs for debugging ACME ordering and challenge issues.

### Key Components

#### Types
- **`ACMEHelper`**: A wrapper struct holding an `*autocert.Manager`. It exposes methods for server startup logic.

#### Functions
- **`NewACMEHelper(m *autocert.Manager)`**: Constructs a new `ACMEHelper` instance from an existing manager.
- **`AcquireCertificate(m *autocert.Manager, hello *tls.ClientHelloInfo)`**: Fetches a TLS certificate. It probes the cache to distinguish between disk hits and CA round-trips, emitting specific log events (`acme_cache_hit`, `acme_issuance_started`, etc.) for observability.
- **`(a *ACMEHelper) WaitForCertificate(ctx context.Context, host string)`**: Waits until a certificate for the specified host is available in the manager's cache or can be obtained. Returns the certificate or an error if the manager is nil.

### Constants
Log event names used in the `event` field of structured logs:
- `EventCacheHit`: Certificate served from local cache.
- `EventIssuanceStarted`: ACME issuance process initiated.
- `EventIssuanceSucceeded`: Certificate successfully acquired from CA.
- `EventIssuanceFailed`: Certificate acquisition failed.