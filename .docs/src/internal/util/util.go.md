<!-- docdaemon ts:2026-10-09T01:40:20Z hash:179fe3cc7adfa5f2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides utility functions for URL manipulation, port parsing, and tracking upstream dial failures to prevent premature tunnel teardown.

### FailureTracker
`FailureTracker` implements a sliding window counter to mitigate transient upstream outages. It records failure timestamps and returns `true` only when the count exceeds a configured threshold within a specific time window. This prevents single-client connection attempts from tearing down tunnels during brief restarts. The tracker resets automatically upon tripping or manually via `Reset()` after a successful operation.

### URL and Port Utilities
*   **EnsurePort**: Validates that a URL contains a port. It injects standard defaults (80 for HTTP, 443 for HTTPS) and returns an error for unsupported schemes like TCP/UDP where defaults are ambiguous.
*   **ParsePort**: Extracts the integer port from a host string, returning a specified default if no port is present. It validates format strictly if a colon is detected without a valid port number.
*   **RewriteHost**: Updates the hostname of a URL while preserving the existing port. It safely handles cases where the new host is empty or `0.0.0.0`.