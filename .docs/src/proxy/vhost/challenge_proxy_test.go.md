<!-- docdaemon ts:2026-10-29T21:04:47Z hash:958bb104e021d3a0 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains end-to-end tests for the ACME HTTP-01 challenge proxying logic in a multi-node cluster.

The tests verify that `serveChallenge` correctly routes validation requests across nodes sharing a hostname via round-robin DNS, ensuring only one hop of forwarding occurs. Key behaviors validated include:

*   **Cluster Routing**: Nodes without the token forward requests to peers holding it, while respecting the `NoProxyParam` to prevent loops or unnecessary forwarding.
*   **Concurrency**: Multiple simultaneous orders are handled correctly, with each node serving its own tokens and proxying others.
*   **Error Handling**: Unknown tokens return 404s from all nodes, and no-proxy requests are answered locally (resulting in 404 if the token isn't local).

The `newRRCluster` helper sets up isolated test environments by swapping DNS lookups and peer dialers to simulate network topology within a single process.