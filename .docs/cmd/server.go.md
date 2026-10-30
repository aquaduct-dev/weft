<!-- docdaemon ts:2026-10-30T02:43:09Z hash:f2efb8bfd3889075 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the `weft server` CLI command, handling startup logic, IP discovery, and graceful lifecycle management.

The `Run` function initializes the server by resolving configuration flags such as `--bind-ip`, `--port`, and `--cloudflare-token`. It invokes `discoverPublicIP` to auto-detect a routable address if none is provided, optionally validating it against external services or local interfaces. If `--bind-interface` is specified, the code uses `netlink` to assign the IP to that interface before starting.

Critical security and operational steps include:
- Writing the generated `connection-secret` to disk if `--secret-file` is set.
- Starting the ACME challenge listener early to ensure reachability for sibling bastions.
- Logging the TLS fingerprint for client-side pinning.

The server runs in a goroutine, blocking until a termination signal (`SIGINT`, `SIGTERM`) or a fatal error occurs, followed by a graceful shutdown with a 10-second timeout. The `init` function registers all subcommand flags with Cobra.