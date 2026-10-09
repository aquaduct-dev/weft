<!-- docdaemon ts:2026-10-09T01:40:51Z hash:b39784c10c9c8e09 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the `weft tunnel` command can successfully establish and route traffic through multiple simultaneous tunnels.

It orchestrates a test environment by launching two local Python HTTP servers, a Weft server, and a Weft tunnel instance configured with two distinct local-to-remote mappings. The script waits for all services to become available, then validates connectivity by curling both remote ports and checking for expected response bodies. It ensures proper cleanup of background processes via a trap on exit.