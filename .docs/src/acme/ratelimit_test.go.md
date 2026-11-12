<!-- docdaemon ts:2026-11-12T09:40:20Z hash:a2ba1ba22bd3c057 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file tests the logic for tracking and enforcing ACME rate limits per host.

It verifies that `rateLimitEnd` correctly parses retry times from both HTTP headers and error details, ensuring only specific CA rate limit errors trigger a hold. The tests confirm that `holdRateLimit` and `rateLimitedUntil` manage state strictly per host and expire exactly when the CA-specified time passes, preventing unnecessary retries while avoiding leakage to unrelated domains.