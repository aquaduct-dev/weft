<!-- docdaemon ts:2026-10-09T01:41:56Z hash:99fb061748e88f4f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `acme` package manages ACME protocol interactions, certificate caching, and peer-to-peer HTTP-01 challenge coordination for automated TLS certificate management.

## Overview
This directory provides the infrastructure for automatic HTTPS via Let's Encrypt or compatible CAs. It wraps `golang.org/x/crypto/acme/autocert` to handle certificate acquisition and caching while ensuring high availability through a custom redirect mechanism in DNS round-robin deployments. The code separates core helper logic from testing utilities to maintain clean dependencies and deterministic test execution.

## Deep Dive
### Certificate Management
The `ACMEHelper` struct wraps an `autocert.Manager`, providing methods to wait for certificate availability and acquire certificates on demand. `AcquireCertificate` probes the cache to distinguish between local hits and CA round-trips, emitting structured logs for observability. This ensures listeners only mount when valid certificates are present.

### Peer Coordination
In distributed environments, ACME validators may hit nodes lacking the necessary key authorization. `RegisterRedirectsLoop` solves this by having nodes POST 301 redirects to peers with higher priority IPs. It queries DNS for A-records, attempts registration via `PostACMERedirect`, and falls back to self-leadership if all peers fail. Trust is established solely via IP verification against DNS records, using TLS without certificate validation.

### Testing Infrastructure
To support deterministic integration tests, `testing_helpers.go` exposes exported functions to swap global DNS lookup and interface address resolution variables. This allows external packages to inject mock network states without modifying production code, ensuring reliable testing of network-dependent logic.

## Key Interfaces
*   `NewACMEHelper(m *autocert.Manager)` — Constructs an ACME helper instance.
*   `AcquireCertificate(m *autocert.Manager, hello *tls.ClientHelloInfo)` — Fetches a TLS certificate, logging cache status.
*   `(a *ACMEHelper) WaitForCertificate(ctx context.Context, host string)` — Blocks until a certificate is available.
*   `RegisterRedirectsLoop` — Starts the background goroutine for peer redirect coordination.
*   `PostACMERedirect` — Sends a registration request to a specific peer address.
*   `SwapLookupIPForTest` / `RestoreLookupIPForTest` — Test seams for mocking DNS lookups.
*   `SwapInterfaceAddrsForTest` / `RestoreInterfaceAddrsForTest` — Test seams for mocking network interfaces.

## Dependencies
*   `zerolog` for structured logging.
*   `golang.org/x/crypto/acme/autocert` for ACME client functionality.
*   Ginkgo v2 and Gomega for BDD-style testing.

## Subcomponents
*   `BUILD.bazel` — Bazel build configuration.
*   `acme.go` — Core certificate helper utilities.
*   `acme_redirect.go` — Peer-to-peer redirect coordination logic.
*   `acme_test.go` — Unit tests for certificate helpers.
*   `acme_redirect_test.go` — Integration tests for redirect logic.
*   `testing_helpers.go` — Exported test seams for network mocking.