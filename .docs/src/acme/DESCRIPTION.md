<!-- docdaemon ts:2026-11-12T09:40:32Z hash:a7855487d33f6a5c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package manages ACME certificate issuance and HTTP-01 challenge validation for round-robin DNS environments.

## Overview
The directory provides a robust wrapper around `autocert.Manager` to handle TLS certificate lifecycle, specifically addressing failures common in distributed clusters where nodes share hostnames via round-robin DNS. It ensures that certificate acquisition respects CA rate limits and that HTTP-01 challenges are correctly resolved even when the validating CA lands on a node that did not initiate the order. By combining local caching, peer-to-peer proxying, and authoritative DNS lookups, it prevents cascading failures and stale cache issues during new host registration.

## Deep Dive
### Certificate Acquisition & Rate Limiting
`acme.go` wraps `autocert.Manager` to provide structured logging and rate-limit protection. The `ACMEHelper` blocks startup until certificates are ready and intercepts runtime handshakes. Crucially, it tracks CA-imposed rate limits per host. If a request fails due to rate limiting, subsequent requests for that host are served locally or blocked until the CA-specified `Retry-After` time elapses, preventing repeated failed attempts from extending the wait period.

### Peer-to-Peer Challenge Proxying
In round-robin setups, only the ordering node holds the key authorization for HTTP-01 challenges. `challenge_proxy.go` implements a fan-out proxy that relays challenge responses from sibling nodes when the current node cannot answer locally. It avoids 301 redirects (which CAs reject for bare IPs) by fetching tokens directly from peers. The system filters out local, loopback, and link-local addresses and caps the fan-out to limit network load.

### DNS Resolution & Challenge Enforcement
To prevent stale NXDOMAIN errors from blocking new hosts, `fresh_lookup.go` queries authoritative nameservers directly instead of relying on the system resolver’s cache. Additionally, `http01_only.go` forces the ACME client to use only HTTP-01 challenges by stripping `tls-alpn-01` from server responses. This is necessary because `tls-alpn-01` fails across nodes that do not hold the specific challenge certificate, quickly hitting authorization failure rate limits.

## Key Interfaces
*   `NewACMEHelper`: Constructs an ACME helper wrapping an autocert manager.
*   `WaitForCertificate`: Blocks until a valid certificate is available or context expires.
*   `AcquireCertificate`: Fetches certificates with detailed logging and rate-limit protection.
*   `FetchChallengeFromPeers`: Proxies HTTP-01 challenges from sibling cluster nodes.
*   `LookupIPFresh`: Resolves hostnames via authoritative nameservers to bypass cached NXDOMAIN.
*   `NewHTTP01OnlyClient`: Creates an ACME client configured to reject TLS-ALPN-01 challenges.

## Dependencies
*   `golang.org/x/crypto/acme`: Core ACME protocol implementation.
*   `github.com/uber-go/automaxprocs` (implied via standard lib): System resource management.
*   `zerolog`: Structured logging infrastructure.
*   `net`, `crypto/tls`: Standard library networking and TLS handling.

## Subcomponents
*   `acme.go`: Core certificate acquisition and rate-limit logic.
*   `challenge_proxy.go`: Peer-to-peer HTTP-01 challenge relay.
*   `fresh_lookup.go`: Authoritative DNS resolution.
*   `http01_only.go`: Transport wrapper to enforce HTTP-01 only.
*   `testing_helpers.go`: Test seams for DNS and network mocking.
*   `*_test.go`: Unit tests for all components.