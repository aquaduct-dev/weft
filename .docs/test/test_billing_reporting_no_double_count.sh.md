<!-- docdaemon ts:2026-10-09T01:40:57Z hash:8dd2672a0a4dcfaf model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the Weft tunneling system does not double-count network traffic in its usage reports.

It orchestrates a mock environment by starting a target HTTP server, a Weft server with reporting enabled, and a tunnel between them. The test sends five 10KB requests through the tunnel and captures the resulting usage logs. A Python helper script then parses these logs to ensure the total reported bytes do not exceed twice the expected volume, confirming accurate accounting without duplication.