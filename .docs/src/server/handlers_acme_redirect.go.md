<!-- docdaemon ts:2026-10-09T01:40:37Z hash:4fe3c08211203516 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the HTTP handler for registering ACME challenge redirects from peer servers.

### Purpose
The `ACMERedirectHandler` processes POST requests to `/acme-redirect` to establish 301 redirects for Let's Encrypt HTTP-01 challenges. It ensures that only authorized peers can redirect traffic by verifying the sender's IP address against the DNS A records of the target host. This trust model relies on public DNS integrity, as an attacker capable of modifying DNS can already obtain certificates via standard HTTP-01 validation.

### Key Components
*   **`lookupIP`**: A test seam variable wrapping `net.LookupIP`, allowing unit tests to mock DNS resolution without affecting production behavior.
*   **`Server.ACMERedirectHandler`**: The main entry point that validates the request method, extracts the host and sender IP, performs DNS verification, and registers the redirect via the Dataplane.

### Behavior
1.  **Validation**: Rejects non-POST requests or missing host parameters with appropriate HTTP error codes.
2.  **Sender Verification**: Parses the remote address to extract the sender's IP. If parsing fails or the IP is invalid, it logs a warning and returns a 400 Bad Request.
3.  **DNS Check**: Resolves the target host's IP addresses. If DNS lookup fails, it returns a 500 Internal Server Error.
4.  **Authorization**: Checks if the sender's IP exists in the resolved DNS set. If not, it returns a 403 Forbidden, logging the offending IP for operator visibility.
5.  **Registration**: Calls `s.Dataplane.RegisterACMERedirect` to apply the redirect configuration. On success, it returns 204 No Content; on failure, it logs the error and returns 500.