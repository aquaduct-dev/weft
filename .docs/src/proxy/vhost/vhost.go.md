<!-- docdaemon ts:2026-10-30T02:43:11Z hash:bf3397fd6e916a71 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a name-based virtual host reverse proxy with support for TLS termination, ACME certificate management, and HTTP/3.

`VHostProxy` manages routes per hostname, applying matchers (path, header, query, method) and modifiers (header injection, redirects, path stripping). It supports three traffic modes: plain HTTP, static TLS (`AddHostWithTLS`), and automated ACME TLS (`AddHostWithACME`). The `VHostProxyManager` coordinates multiple proxies, handling ACME challenge listeners and certificate caching.

Key behaviors include:
- **Route Selection**: Uses longest-prefix matching to resolve overlapping paths on the same host.
- **TLS & ALPN**: Advertisements are configured dynamically based on enabled protocols (HTTP/2, HTTP/3). ACME challenges are served via `autocert` or proxied to sibling nodes in round-robin DNS setups.
- **WireGuard Integration**: `WGAwareRoundTripper` routes upstream requests through a userspace WireGuard device if the target is in the `10.1.*` range, with failure tracking to trigger tunnel cleanup.
- **HTTP/3**: Served on a separate UDP listener alongside TCP, advertised via `Alt-Svc`. Disabled by default for internal WireGuard hosts.
- **Health Checks**: `CanPassACMEChallenge` probes public IPv4 records to ensure ACME HTTP-01 reachability before issuance.