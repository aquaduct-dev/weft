<!-- docdaemon ts:2026-11-12T09:10:30Z hash:d3375014d328b189 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a name-based virtual host reverse proxy with automatic TLS termination, HTTP/2 and HTTP/3 support, and ACME challenge handling.

`VHostProxy` manages routing for multiple hosts on a single port, dispatching requests to `Route` objects defined by matchers (path, header, query, method) and modifiers (header injection, redirects, path stripping). It supports three TLS modes: static PEM certificates (`AddHostWithTLS`), Let's Encrypt via ACME (`AddHostWithACME`), or plain HTTP. The ACME implementation uses the HTTP-01 challenge exclusively to avoid failures in round-robin DNS setups, probing all public IPv4 records to ensure reachability before issuance.

Key components include:
*   **Routing Logic**: `findRoute` selects the most specific matching route based on path prefix length, adhering to Gateway-API precedence rules.
*   **Protocol Support**: Automatically negotiates HTTP/2 over TLS and serves HTTP/3 (QUIC) on UDP for public listeners, while keeping internal WireGuard routes on HTTP/1.1.
*   **WireGuard Integration**: `WGAwareRoundTripper` routes upstream traffic through a userspace NetStack if the target is in the `10.1.*` range, with failure tracking to trigger tunnel cleanup.
*   **Lifecycle Management**: `VHostProxyManager` coordinates multiple proxies, caching certificates and exposing status endpoints for certificate validity and ACME failure reporting.