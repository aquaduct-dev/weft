<!-- docdaemon ts:2026-10-09T01:40:15Z hash:4a5ea914afac941d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a Go client library for programmatically managing Weft server tunnels via administrative HTTP endpoints.

The `Client` struct encapsulates the connection details and HTTP state required to interact with the Weft server. It handles URL parsing, default port assignment, and authentication flow using JWTs obtained via the `auth` package.

### Key Types
- **`TunnelInfo`**: Struct representing tunnel metrics (TX/RX bytes) and source/destination URLs.
- **`Client`**: The main interface for performing administrative actions. It stores the server URL, connection secret, and target tunnel name.

### Functions
- **`NewClient(weftURLStr, tunnelName string)`**: Initializes a new client. It parses the provided URL, ensures a default port (`9092`) is set, and extracts the connection secret from the URL user info. If no specific `tunnelName` is given, it defaults to generic admin behavior.
- **`ensureAuth()`**: Lazily initializes the HTTP client by calling `auth.Login`. It uses `"admin-client"` as the proxy name for generic operations if `tunnelName` is empty; otherwise, it uses the specific tunnel name to scope the JWT.
- **`ListTunnels()`**: Sends a POST request to `/list` to retrieve active tunnels. It returns a map of tunnel names to their `TunnelInfo`. Authentication uses the generic admin context.
- **`Shutdown()`**: Sends a POST request to `/shutdown` for the specific tunnel defined in the client's `tunnelName`. It validates that a tunnel name was provided during initialization before attempting authentication and the request.