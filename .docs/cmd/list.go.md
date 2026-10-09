<!-- docdaemon ts:2026-10-09T01:40:01Z hash:ffb74ac0707809b2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `weft list` CLI command to retrieve and display active tunnels from a Weft server.

### Purpose
The `listCmd` Cobra command authenticates with a specified server, retrieves tunnel statistics via the `/list` endpoint, and formats the output as a table. It handles connection setup, error reporting, and optional human-readable byte formatting.

### Key Components
- **`listCmd`**: The primary Cobra command definition. It parses the server URL, extracts credentials from the userinfo component, and performs an HTTP POST to fetch JSON data.
- **`formatBytes`**: Helper function that converts byte counts into human-readable strings (e.g., "1.2 KiB").
- **`init`**: Registers the `--human-readable` (`-l`) flag and adds the command to the root CLI.

### Workflow
1. **Authentication**: Uses `auth.Login` with the server host and user-provided secret to obtain a JWT client.
2. **Request**: Sends a POST request to `<server>/list`.
3. **Processing**: Parses the JSON response into a map of tunnel info, sorts tunnels by ID in reverse order, and prints them using `tabwriter`.
4. **Error Handling**: Logs fatal errors for invalid URLs, login failures, or non-OK HTTP status codes, printing the error body to stderr.