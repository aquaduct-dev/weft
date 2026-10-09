<!-- docdaemon ts:2026-10-09T01:40:57Z hash:cae586a9445d3f14 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the weft server correctly reports usage metrics for multiple concurrent tunnels from a single client upon graceful shutdown.

It orchestrates a test environment by launching two mock HTTP target servers and a weft server with reporting enabled. Two distinct tunnels are established, each mapping to one of the target servers. The script generates specific traffic volumes on both tunnels to ensure data accumulation. After gracefully stopping the tunnels, it inspects the generated report file to confirm that entries exist for both tunnel names, sources, and destinations, ensuring accurate multi-tunnel billing or logging behavior.