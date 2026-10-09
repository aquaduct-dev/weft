<!-- docdaemon ts:2026-10-09T01:40:53Z hash:7debf2d79aa6449b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the `--retries` flag correctly triggers tunnel shutdown after consecutive healthcheck failures.

It simulates a server crash to force healthcheck errors, ensuring the tunnel exits within a 45-second window. The test validates both the adaptive retry logic and specific log messages indicating failure detection and graceful termination.