<!-- docdaemon ts:2026-10-09T01:40:46Z hash:cd50a46e068b0ef1 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains Ginkgo integration tests verifying that the server automatically removes tunnels when their backend endpoints become unreachable.

It sets up a mock backend HTTP server and a tunnel server instance, authenticates to obtain a token, and establishes a WireGuard tunnel. The test suite validates the lifecycle of the tunnel by confirming its presence in the server's list immediately after connection. It then simulates a backend failure by closing the listener and server, waiting for the server's periodic connectivity checks (approximately 30 seconds) to detect the outage, and finally asserting that the tunnel is removed from the active list.