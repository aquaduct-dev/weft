<!-- docdaemon ts:2026-11-01T18:05:39Z hash:8a644d227be6964b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements a name-based virtual host reverse proxy with automatic TLS management and HTTP/3 support.

## Overview
The `vhost` package manages dynamic route registration, ACME-based certificate issuance, and multi-protocol termination for the weft bastion nodes. It enables multiple hosts to share a single IP by routing requests based on hostname, path prefixes, and headers while handling complex distributed ACME challenges across cluster peers. The system ensures robustness against race conditions, network failures, and round-robin DNS distribution during tunnel establishment.

## Deep Dive
### Virtual Host Routing
Requests are matched against registered routes using `PathMatcher`, `HeaderMatcher`, or `MethodMatcher`. The longest matching path prefix takes precedence to prevent catch-all routes from shadowing specific subpaths. Routes forward traffic via `WGAwareRoundTripper`, which uses WireGuard netstack dialing for internal targets and standard transport otherwise. Path modifiers strip prefixes cleanly, normalizing dot-segments to ensure upstream services receive valid URLs.

### ACME Certificate Management
TLS certificates are issued automatically via Let's Encrypt using the ACME protocol. The flow binds port 80 first to satisfy HTTP-01 challenges, then probes public IPs to verify reachability across round-robin DNS records. If issuance fails, errors are recorded in `ACMEFailures` and exposed via `/certificates`. Successful issuance starts the TLS listener in the background, while failures trigger cleanup of associated tunnels.

### Distributed Challenge Proxy
To handle round-robin DNS where validators may land on any node, HTTP-01 challenges are proxied among sibling bastions. A node lacking the challenge token queries peers via `acme.FetchChallengeFromPeers`. Requests marked with `NoProxyParam` are answered locally only, preventing infinite forwarding loops. Unmanaged hosts fall through to the backend if configured, allowing external ACME clients to complete their own validations.

### Metering and Observability
Traffic metrics are tracked at both connection and application layers. For HTTP/1.1 and HTTP/2, byte counts are captured via wrapped connections beneath TLS termination. HTTP/3 metering occurs at the application layer, wrapping request bodies and response writers to track streaming data accurately. Active request tracking ensures long-lived transfers do not under-report usage. Error logs filter noisy TLS handshake failures to debug level, surfacing other server errors as warnings.

## Key Interfaces
*   `VHostProxyManager`: Manages route registration, ACME issuance, and certificate lifecycle.
*   `VHostProxy`: Handles request routing, TLS termination, and upstream forwarding per host.
*   `MeteredServer`: Wraps `http.Server` to provide transparent byte-metering for all protocols.
*   `PathMatcher`: Performs segment-aware prefix matching for route selection.
*   `httpErrorLogWriter`: Filters and structures net/http error messages for zerolog integration.

## Dependencies
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `golang.org/x/crypto/acme/autocert`: Let's Encrypt certificate management.
*   `go.uber.org/zap` / `zerolog`: Structured logging.
*   `github.com/ginkgo-ginkgo/ginkgo/v2` & `gomega`: Testing framework.
*   Standard library: `net/http`, `crypto/tls`, `sync`, `io`.

## Subcomponents
*   `vhost.go`: Core proxy implementation and route management.
*   `challenge_proxy.go`: Distributed HTTP-01 challenge forwarding logic.
*   `errorlog.go`: Custom HTTP error log writer.
*   `meter/`: Byte-metering components for HTTP/1.1, HTTP/2, and HTTP/3.
*   `BUILD.bazel`: Bazel build targets for library and tests.
*   `*_test.go`: Comprehensive test suite covering concurrency, routing, and ACME flows.