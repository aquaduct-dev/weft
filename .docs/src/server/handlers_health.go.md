<!-- docdaemon ts:2026-10-09T01:40:39Z hash:d55b6525c44aaf6c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the HTTP handler for receiving and processing health check reports from registered proxies.

### Purpose
The `HealthcheckHandler` function serves as the entry point for clients to report their operational status to the server. It validates incoming requests, authenticates the caller via JWT, verifies peer existence, updates the last-seen timestamp, and returns a confirmation response.

### Key Components

#### `HealthcheckHandler`
*   **Method Validation**: Rejects non-POST requests with `405 Method Not Allowed`.
*   **Request Parsing**: Decodes the JSON body into `types.HealthcheckRequest`. Returns `400 Bad Request` if decoding fails (excluding EOF).
*   **Authentication**: Extracts the proxy name from the JWT subject using `getJWTSubjectFromRequest`. Returns `400 Bad Request` if the subject is missing.
*   **Peer Verification**: Checks if the proxy exists in `s.Store`. Returns `404 Not Found` if the peer is unknown.
*   **State Update**: Updates the peer's last seen time in the store using `time.Now()`.
*   **Response**: Returns a `200 OK` JSON response containing the status ("healthy") and a message confirming the proxy's health, IP address, and the received request message.

### Integration
This handler interacts with the `Server` struct's `Store` for peer management and relies on `types.HealthcheckRequest` and `types.HealthcheckResponse` for data structure definitions. It assumes the presence of JWT middleware or context that populates the token for subject extraction.