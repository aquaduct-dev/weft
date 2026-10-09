<!-- docdaemon ts:2026-10-09T01:40:08Z hash:6f2dc19e0d9d6766 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains the Ginkgo test suite for the ACME helper, validating certificate acquisition logic and event constants.

It verifies `NewACMEHelper` construction and error handling when the manager is unconfigured. The suite uses a `fakeCache` to simulate autocert cache behaviors, ensuring correct responses for hits, misses, and parse failures during `WaitForCertificate`. It also tests `AcquireCertificate` against nil managers and invalid domains, confirming that errors are surfaced correctly without panics. Finally, it asserts the stability of event name constants used in logging pipelines.