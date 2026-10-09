<!-- docdaemon ts:2026-10-09T01:40:16Z hash:ea5b6151872017a1 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `dns` Go library, which provides DNS resolution capabilities using Cloudflare and Zerolog.

### Purpose
The `BUILD.bazel` file configures the `go_library` target named `dns`. It compiles `cloudflare.go` into a reusable Go package located at `github.com/aquaduct-dev/weft/src/dns`. The target is marked public to allow other packages in the repository to depend on it.

### Dependencies
The library relies on two external dependencies:
- **Cloudflare Go SDK**: Provides the underlying client for interacting with Cloudflare's DNS API.
- **Zerolog**: Used for structured logging within the DNS module.

### Integration
This module serves as the DNS abstraction layer for the Weft project. By isolating Cloudflare-specific logic in `cloudflare.go`, it allows the rest of the application to interact with DNS services through a consistent interface while leveraging Cloudflare's infrastructure.