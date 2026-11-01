<!-- docdaemon ts:2026-11-01T18:05:29Z hash:65953f6d750bdd9b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a name-based virtual host reverse proxy with support for HTTP/1.1, HTTP/2, and HTTP/3, including automatic TLS certificate management via ACME.

The `VHostProxy` manages routes per hostname, matching requests using `PathMatcher`, `HeaderMatcher`, or `MethodMatcher`. It applies `Modifier`s like header injection or path prefix stripping before forwarding to upstream targets via `WGAwareRoundTripper`, which handles WireGuard netstack dialing and failure-based tunnel cleanup.

TLS termination is handled through `AddHostWithTLS` (static certs) or `AddHostWithACME` (Let's Encrypt). The ACME flow binds port 80 first to satisfy HTTP-01 challenges, then probes public IPs to ensure reachability across round-robin DNS records. If issuance succeeds, it starts the TLS listener in the background.

HTTP/2 and HTTP/3 are enabled by default but can be disabled via environment variables. HTTP/3 uses a separate UDP listener. Route selection prioritizes the longest path prefix match to prevent catch-all routes from shadowing specific ones.