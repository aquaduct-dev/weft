<!-- docdaemon ts:2026-10-09T01:40:54Z hash:e8093d3fbc6dcb2d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script validates that the Weft tunnel correctly issues HTTP 302 redirects to a specified target URL.

It orchestrates a test environment by launching a static HTTP server, the Weft server (which generates a connection secret), and the Weft tunnel. The tunnel maps a remote path (`/test`) to a local redirect target. Finally, it sends a request through the tunnel and verifies that the response contains the expected `302 Found` status code and `Location` header pointing to the configured target.