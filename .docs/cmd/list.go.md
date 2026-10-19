<!-- docdaemon ts:2026-10-19T23:25:44Z hash:75304bf5eecdced2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `weft list` CLI command to retrieve and display active tunnels from a server.

The `listCmd` Cobra command parses an optional server URL, defaulting port 9092 if omitted. It extracts credentials from the URL's userinfo component to authenticate via `auth.Login`, exchanging them for a JWT. The command then POSTs to the server’s `/list` endpoint. If the server returns a non-OK status, the response body is printed to stderr before exiting.

On success, the JSON response is unmarshaled into a map of tunnel information. Results are sorted by tunnel ID in reverse alphabetical order and displayed in a tabular format using `tabwriter`. A `--human-readable` (shorthand `-l`) flag allows byte counts to be formatted as KiB/MiB/GiB instead of raw integers.