<!-- docdaemon ts:2026-10-19T23:25:52Z hash:1b00d2905e1a2da3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file tests that `AddHostWithACME` correctly handles asynchronous ACME certificate issuance failures and successes.

It verifies the async contract where `AddHostWithACME` returns immediately, while background goroutines handle TLS setup. The tests ensure that:

1.  **Failure Recording**: If the ACME helper fails (e.g., rate limited), the error is recorded in `ACMEFailures()` with host and stage details, and the tunnel cleanup is triggered.
2.  **Success Clearing**: A subsequent successful issuance for a previously failed host clears the failure record.

Key test helpers include `withACMEStubs` to replace certificate waiting and redirect loop logic, and `newACMETestManager` to set up a manager with mocked cleanup channels and ACME challenge probes.