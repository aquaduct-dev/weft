<!-- docdaemon ts:2026-10-19T23:25:55Z hash:3d3e144701217c29 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `CertificatesHandler` to verify how it reports ACME issuance failures.

The tests ensure that `GET /certificates` correctly exposes background ACME errors alongside cached certificates. Specifically, `TestCertificatesHandler_ReportsACMEFailures` verifies that when a host has a recorded failure (e.g., rate limiting), the response includes the host, error message, and timestamp in the `ACMEFailures` field. This behavior supports the design where issuance runs asynchronously; if the goroutine fails, the error is stored and surfaced via this endpoint.

`TestCertificatesHandler_OmitsEmptyACMEFailures` confirms that the `acme_failures` field is omitted from the JSON response entirely when there are no failures, keeping the payload clean for healthy states.