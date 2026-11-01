<!-- docdaemon ts:2026-11-01T18:06:03Z hash:2bc44462e8589a61 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package manages TLS certificate acquisition and HTTP-01 challenge validation for round-robin DNS environments.

## Overview
The ACME module simplifies HTTPS listener setup by wrapping `autocert.Manager` to ensure certificates are available before mounting listeners. It specifically addresses failures in round-robin DNS setups where only the node placing an order holds the challenge key, causing other nodes to fail `tls-alpn-01` validation and hit rate limits. The system forces HTTP-01 usage and proxies challenges between sibling nodes to ensure successful authentication regardless of which node the CA validator contacts.

## Deep Dive
### Certificate Acquisition
`ACMEHelper` wraps `autocert.Manager` to provide structured logging for certificate lifecycle events (`acme_cache_hit`, `acme_issuance_started`). It exposes `WaitForCertificate` to block until a cert is ready and `AcquireCertificate` to handle TLS handshakes, distinguishing between cache hits and new CA round-trips.

### HTTP-01 Enforcement
In round-robin DNS, `tls-alpn-01` fails on non-leader nodes because they lack the specific challenge certificate. `HTTP01OnlyTransport` intercepts ACME JSON responses, stripping `tls-alpn-01` challenges to force immediate fallback to `http-01`. This prevents rapid authorization failures that trigger Let's Encrypt rate limits.

### Peer Challenge Proxying
When a node receives an HTTP-01 challenge it cannot answer locally, `FetchChallengeFromPeers` queries all sibling nodes in parallel. It uses a `weft-redirect=true` parameter to prevent recursive loops and filters out loopback/link-local IPs. This ensures the CA validator gets a valid response from any node in the rotation without relying on redirects, which CAs reject for bare IPs.

## Key Interfaces
- `NewACMEHelper(m *autocert.Manager)` constructs the helper wrapper.
- `AcquireCertificate(m *autocert.Manager, hello *tls.ClientHelloInfo)` fetches certs with observability logs.
- `WaitForCertificate(ctx context.Context, host string)` blocks until a certificate is available.
- `FetchChallengeFromPeers(path string)` fans out HTTP requests to siblings to find the key auth token.
- `NewHTTP01OnlyClient()` returns an ACME client configured to ignore TLS-ALPN-01 challenges.
- `SwapLookupIPForTest`, `SwapInterfaceAddrsForTest`, `SwapDialPeerForTest` export test seams for mocking network behavior.

## Dependencies
- `golang.org/x/crypto/acme/autocert`: Core certificate management.
- `zerolog`: Structured event logging.
- `net/http`, `crypto/tls`: Standard library networking and TLS handling.

## Subcomponents
- `acme.go`: Helper utilities and log event constants.
- `challenge_proxy.go`: Fan-out proxy logic for sibling nodes.
- `http01_only.go`: Transport wrapper to strip TLS-ALPN-01.
- `testing_helpers.go`: Exported mock functions for DNS and dialing.