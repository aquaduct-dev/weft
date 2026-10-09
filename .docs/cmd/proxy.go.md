<!-- docdaemon ts:2026-10-09T01:40:02Z hash:e0c5236312d5c8b6 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the `proxy` subcommand for the CLI, enabling users to create a temporary proxy between two URLs.

### Purpose
The `proxyCmd` Cobra command facilitates one-off proxying from a source URL to a destination URL. It handles argument parsing, URL validation, and lifecycle management of the proxy instance.

### Key Functions
*   **`init`**: Registers the `proxy` command with the root command and adds the `--proxy-name` flag.
*   **`Run`**: The main execution logic. It parses the source and destination URLs, generates a default name using SHA-256 if not provided, starts the proxy via `proxy.NewProxyManager`, and blocks until a shutdown signal (SIGINT/SIGTERM) is received.

### Integration
This file acts as the entry point for the proxy feature within the application's CLI structure, delegating actual proxy operations to the `github.com/aquaduct-dev/weft/src/proxy` package.