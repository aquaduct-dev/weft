<!-- docdaemon ts:2026-10-15T20:41:53Z hash:d16c91319d14e8c3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `weft proxy` CLI command to run local source-to-destination proxies within a single process.

### Purpose
The `proxy.go` file defines the Cobra command for creating one-off URL proxies without involving a weft server or WireGuard. It supports multiple src/dst pairs and optional static TLS termination via provided certificate files, falling back to ACME if no static certs are given.

### Key Components
*   **`proxyCmd`**: The main Cobra command structure. It validates that arguments are provided in even-numbered pairs (src, dst).
*   **`readTLSPair`**: Helper function that loads PEM-encoded certificate and key files from disk based on `--tls-cert` and `--tls-key` flags. It ensures both paths are provided together or neither is.
*   **`init`**: Registers flags (`proxy-name`, `tls-cert`, `tls-key`) and attaches the command to the root CLI.

### Behavior
1.  **Proxy Creation**: Iterates through argument pairs, parsing URLs and generating unique names (SHA256 hash of src|dst) unless a specific `--proxy-name` is set for a single pair.
2.  **TLS Handling**: Passes loaded cert/key bytes to `proxy.NewProxyManager().StartProxy`. If nil, the underlying proxy uses ACME.
3.  **Lifecycle Management**: Starts all proxies, then blocks on SIGINT/SIGTERM signals. Upon signal receipt, it gracefully closes all active proxies before exiting.