<!-- docdaemon ts:2026-10-29T21:04:49Z hash:ce97b6eff774faa3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a name-based virtual host reverse proxy with support for TLS termination, ACME certificate management, and HTTP/3.

`VHostProxy` manages routes per hostname, applying matchers (path, header, query, method) and modifiers (header injection, redirects, path stripping). It supports three TLS modes: static PEM certificates (`AddHostWithTLS`), automatic ACME issuance via Let's Encrypt (`AddHostWithACME`), or no TLS. The `VHostProxyManager` coordinates multiple proxies on different ports and handles ACME challenge routing.

Key features include:
- **Route Matching**: Uses longest-prefix precedence for overlapping paths.
- **WireGuard Integration**: Routes traffic to internal `10.1.*` addresses through a userspace device, with automatic tunnel cleanup on sustained dial failures.
- **Protocol Support**: Defaults to HTTP/2 and HTTP/3 (QUIC) for public listeners, falling back to HTTP/1.1. WebSockets are handled over HTTP/1.1 to avoid compatibility issues with Extended CONNECT.
- **ACME Robustness**: Probes DNS-resolved IPs before issuing certificates to ensure reachability, handling round-robin DNS by requiring a majority of records to respond.