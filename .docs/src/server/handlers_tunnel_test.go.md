<!-- docdaemon ts:2026-10-09T01:40:40Z hash:b3a3e062ace96246 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `ConnectHandler` to verify JWT-based authorization logic and tunnel name validation.

### Purpose
The tests ensure that the `ConnectHandler` correctly enforces security constraints regarding JWT claims, specifically validating that the token's subject (`sub`) matches the requested tunnel name. It also verifies behavior for missing subjects and backward compatibility when tunnel names are omitted.

### Key Components

*   **`makeJWTRequest`**: A test helper that constructs an `*http.Request` with a pre-signed JWT in the context. This bypasses middleware to allow direct handler invocation during testing.
*   **`TestConnectHandler_RejectsMismatchedTunnelName`**: Verifies that a request is rejected (403) if the JWT subject does not match the `TunnelName` in the request body.
*   **`TestConnectHandler_DefaultsTunnelNameFromSub`**: Ensures that if `TunnelName` is omitted from the request, the handler defaults to the JWT subject without returning a 403 error.
*   **`TestConnectHandler_RejectsMissingSubject`**: Confirms that requests with empty or missing JWT subjects are rejected (401).