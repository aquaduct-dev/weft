<!-- docdaemon ts:2026-11-12T09:11:07Z hash:a5fcb217c90d351f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package manages TLS certificate acquisition and HTTP-01 challenge validation across a cluster of bastion nodes.

## Overview
The ACME helper simplifies HTTPS listener setup by wrapping `autocert.Manager` to ensure certificates are available before mounting listeners. It addresses specific challenges in round-robin DNS environments where multiple nodes share a hostname, ensuring that only the node holding the order can complete validation without hitting rate limits or causing CA rejections due to redirects.

## Deep Dive
### Certificate Acquisition
`ACMEHelper` wraps `autocert.Manager` to provide structured logging for certificate lifecycle events, distinguishing between cache hits and CA round-trips. The `WaitForCertificate` method blocks until a certificate is available, while `AcquireCertificate` emits specific log events for observability.

### HTTP-01 Challenge Proxying
In clusters with round-robin DNS, Let's Encrypt validators may hit any node, but only the ordering node holds the key authorization. Instead of using 301 redirects (which CAs reject for bare IPs), this module implements a fan-out proxy. When a node cannot answer locally, it fetches the token from sibling nodes via parallel HTTP requests, ensuring validation succeeds regardless of which node the CA contacts.

### Transport Hardening
To prevent `tls-alpn-01` failures caused by multiple nodes attempting simultaneous authorizations on port 443, the package provides an HTTP transport wrapper. This transport intercepts ACME responses and strips `tls-alpn-01` challenges, forcing the client to use `http-01` exclusively. This avoids rate limit exhaustion when non-ordering nodes fail ALPN validation.

### Fresh DNS Resolution
New hosts often trigger certificate requests immediately after DNS registration, risking stale NXDOMAIN cache entries from the system resolver. The `LookupIPFresh` function bypasses local caches by querying authoritative nameservers directly for the host's zone. If authoritative servers confirm the record exists, resolution proceeds; otherwise, it falls back to the standard resolver.

## Key Interfaces
- `NewACMEHelper(m *autocert.Manager)` constructs a new helper instance.
- `AcquireCertificate(m *autocert.Manager, hello *tls.ClientHelloInfo)` fetches a TLS certificate with logging.
- `(a *ACMEHelper) WaitForCertificate(ctx context.Context, host string)` waits for certificate availability.
- `FetchChallengeFromPeers` fans out parallel requests to siblings to resolve HTTP-01 challenges.
- `LookupIPFresh` resolves hostnames via authoritative nameservers to avoid cached NXDOMAIN errors.
- `NewHTTP01OnlyClient` returns an ACME client configured to force HTTP-01 validation.

## Dependencies
- `golang.org/x/crypto/acme/autocert`
- `golang.org/x/crypto/acme`
- `zerolog` for structured event logging
- Ginkgo/Gomega for testing

## Subcomponents
- `acme.go`: Core helper utilities and certificate management.
- `challenge_proxy.go`: Fan-out proxy for peer-to-peer challenge forwarding.
- `fresh_lookup.go`: Authoritative DNS resolution to bypass cache.
- `http01_only.go`: Transport wrapper to enforce HTTP-01 validation.
- `testing_helpers.go`: Test seams for mocking DNS and network behavior.