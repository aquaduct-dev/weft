<!-- docdaemon ts:2026-10-29T21:06:05Z hash:c6a794fadaa66c67 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package manages ACME certificate acquisition, caching, and HTTP-01 challenge resolution across cluster nodes.

## Overview
The `acme` directory provides utilities for automating TLS certificate management using Let's Encrypt via the `autocert` library. It ensures certificates are available before listeners start and emits structured logs for observability. In clustered environments with round-robin DNS, it solves the problem of validators hitting non-authoritative nodes by proxying HTTP-01 challenges to peers that hold the key authorization, avoiding rejected bare-IP redirects.

## Deep Dive
### Certificate Lifecycle Management
`ACMEHelper` wraps `autocert.Manager` to simplify HTTPS setup. `AcquireCertificate` probes the cache to distinguish between local hits and CA round-trips, emitting specific events (`acme_cache_hit`, `acme_issuance_started`) for debugging. `WaitForCertificate` blocks until a cert is ready, ensuring safe listener mounting.

### Peer-to-Peer Challenge Proxy
When a node receives an HTTP-01 challenge but lacks the token (because another node placed the order), it fans out requests to all sibling nodes in parallel. This bypasses the limitation where Let's Encrypt rejects 301 redirects to bare IPs. The proxy filters out loopback and link-local addresses to prevent internal traffic loops and enforces strict timeouts and body size limits to prevent resource exhaustion. A `weft-redirect=true` parameter ensures peers respond from local state only.

## Key Interfaces
*   `NewACMEHelper(m *autocert.Manager)` - Constructs the helper instance.
*   `AcquireCertificate(m *autocert.Manager, hello *tls.ClientHelloInfo)` - Fetches or caches a TLS certificate.
*   `(a *ACMEHelper) WaitForCertificate(ctx context.Context, host string)` - Blocks until the certificate is available.
*   `FetchChallengeFromPeers(path string)` - Proxies HTTP-01 challenges to sibling nodes.
*   `SwapLookupIPForTest`, `SwapInterfaceAddrsForTest`, `SwapDialPeerForTest` - Test seams for mocking network behavior.

## Dependencies
*   `golang.org/x/crypto/acme/autocert` - Core ACME protocol implementation.
*   `github.com/rs/zerolog` - Structured logging.
*   Ginkgo and Gomega - Testing framework.

## Subcomponents
*   `acme.go` - Certificate acquisition and caching logic.
*   `challenge_proxy.go` - Fan-out proxy for HTTP-01 challenges.
*   `testing_helpers.go` - Exported test seams for network mocking.
*   `*_test.go` - Unit tests for both modules.