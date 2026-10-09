<!-- docdaemon ts:2026-10-09T01:40:48Z hash:7bfe1d32fb184619 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains Ginkgo integration tests that validate HTTP, HTTPS, and TCP tunneling capabilities of the server.

The test suite spins up an in-process `server.Server` alongside a dummy backend to verify end-to-end connectivity. It uses `openPort` to allocate ephemeral ports for isolation and `auth.GetToken` with `Eventually` to handle startup race conditions. Key scenarios include forwarding HTTP/HTTPS traffic through WireGuard tunnels and verifying usage reporting via a mock HTTP client. The tests also ensure DNS updates trigger correctly when Cloudflare credentials are configured and that domain resolution functions as expected.