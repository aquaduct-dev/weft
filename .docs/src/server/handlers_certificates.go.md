<!-- docdaemon ts:2026-10-19T23:25:56Z hash:cac7ad595790e3f8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `GET /certificates` endpoint to expose cached TLS certificates and ACME issuance status.

The `CertificatesHandler` method serves as the primary entry point for retrieving certificate data. It enforces HTTP GET restrictions and delegates data retrieval to the `Dataplane` interface, specifically calling `ListCertificates` for active certs and `ListACMEFailures` for recent errors.

The handler logs debug information when both certificates and ACME failures are present, indicating a state where some hosts have valid certs while others are experiencing issuance issues. This behavior stems from background goroutines that continue attempting ACME challenges even after initial setup, logging failures to the `VHostProxyManager` until resolved.

The response is encoded as JSON using `types.CertificatesResponse`, which aggregates the list of certificates and any associated ACME failure records. The endpoint is JWT-gated, consistent with other admin routes defined in the server mux.