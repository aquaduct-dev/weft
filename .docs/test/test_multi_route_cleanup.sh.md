<!-- docdaemon ts:2026-10-09T01:41:03Z hash:7049c8a9d70359af model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script validates that the Weft server correctly isolates and cleans up individual tunnels when one is terminated while others remain active.

It spins up two independent Python HTTP upstreams and a central Weft server, then establishes two distinct tunnels mapping different paths to those upstreams. After confirming both routes serve data correctly, it terminates the first tunnel via SIGTERM and verifies that its route returns 404 while the second tunnel remains fully operational. This ensures no cross-contamination or resource leaks occur during partial teardown.