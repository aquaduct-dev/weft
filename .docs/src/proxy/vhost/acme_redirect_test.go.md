<!-- docdaemon ts:2026-10-09T01:40:22Z hash:5e20aae74a94fe99 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the ACME challenge redirection logic within the `VHostProxyManager`.

It verifies that peer redirects are registered, looked up, and expired correctly. It also validates the `tryRedirectChallenge` behavior, ensuring requests to peer hosts are redirected to their highest IP, while requests to local ACME hosts or failed lookups fall through without modification.