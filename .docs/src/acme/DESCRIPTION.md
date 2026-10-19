<!-- docdaemon ts:2026-10-19T23:27:09Z hash:f801d9186cdede59 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package manages ACME TLS certificate acquisition and coordinates HTTP-01 challenge redirects across a cluster of nodes.

## Overview
The `acme` directory provides utilities for automated HTTPS certificate management using `autocert`. It ensures that certificates are available before listeners start and emits structured logs for lifecycle auditing. In distributed deployments, it solves the problem of DNS round-robin validation by allowing nodes to redirect unvalidated challenges to peers that hold the necessary key material.

## Deep Dive
### Certificate Acquisition
The `ACMEHelper` wraps `autocert.Manager` to simplify server setup. It exposes `WaitForCertificate` to block until a cert is cached or acquired, and `AcquireCertificate` to handle the actual fetch. Structured logging distinguishes between cache hits and CA round-trips, aiding in debugging issuance failures.

### Peer-to-Peer Redirects
In DNS round-robin scenarios, validators may hit nodes without the `keyAuth`. The `RegisterRedirectsLoop` periodically queries DNS for A-records and POSTs to higher-priority peers to register 301 redirects. If all higher peers are unreachable, the node declares itself the leader. Trust is established via IP verification against DNS records, with TLS used only for transport (`InsecureSkipVerify`).

### Test Seams
To enable deterministic testing of network-dependent logic, `testing_helpers.go` exports functions to swap `net.LookupIP` and interface address resolution. These seams allow tests to simulate dead peers, specific local bindings, and DNS states without affecting production code.

## Key Interfaces
- `NewACMEHelper(m *autocert.Manager)`: Constructs an ACME helper instance.
- `AcquireCertificate(m *autocert.Manager, hello *tls.ClientHelloInfo)`: Fetches a TLS certificate, emitting log events.
- `(a *ACMEHelper) WaitForCertificate(ctx context.Context, host string)`: Waits for a certificate to become available.
- `RegisterRedirectsLoop(ctx context.Context)`: Starts the background loop for peer coordination.
- `PostACMERedirect(addr, host string)`: Sends a redirect registration request to a peer.
- `SwapLookupIPForTest(fn func(string) ([]net.IP, error))`: Replaces DNS lookup for testing.
- `SwapInterfaceAddrsForTest(fn func() ([]net.Interface, error))`: Replaces interface enumeration for testing.

## Dependencies
- `golang.org/x/crypto/acme/autocert`
- `github.com/rs/zerolog` (structured logging)
- Standard library `net`, `crypto/tls`, `context`

## Subcomponents
- `acme.go`: Core certificate acquisition logic.
- `acme_redirect.go`: Peer coordination and redirect logic.
- `testing_helpers.go`: Exported test seams for network simulation.
- `acme_test.go`: Unit tests for certificate handling.
- `acme_redirect_test.go`: Integration tests for peer coordination.
- `BUILD.bazel`: Bazel build definitions.