<!-- docdaemon ts:2026-10-29T21:04:44Z hash:864fc3f3c02af570 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file tests that `AddHostWithACME` correctly handles asynchronous ACME certificate issuance failures and successes.

The test suite verifies the background goroutine's error reporting contract. It ensures that when ACME issuance fails, the failure is recorded in `ACMEFailures`, the associated tunnel is cleaned up, and subsequent successful issuance clears previous errors.

### Key Functions

*   **`withACMEStubs`**: Temporarily replaces `waitForCertificateFn` to control ACME helper behavior (success or failure) within a test scope.
*   **`newACMETestManager`**: Initializes a `VHostProxyManager` with a temporary cache directory, a specific ACME port, and a mock cleanup channel to verify tunnel teardown.
*   **`TestAddHostWithACME_RecordsFailingIssuance`**: Confirms that a failing ACME stub triggers tunnel cleanup and records the error details (host, stage, error message) in the manager's failure log.
*   **`TestAddHostWithACME_SuccessClearsPreviousFailure`**: Verifies that a successful issuance after a prior failure clears the recorded error state from `ACMEFailures`.