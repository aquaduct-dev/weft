<!-- docdaemon ts:2026-10-19T23:25:57Z hash:aa6d5bf4fb9fee18 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a name-based virtual host reverse proxy with optional TLS termination, ACME certificate management, and HTTP/3 support.

`VHostProxy` manages routing for multiple hosts on a single port, supporting both plain HTTP and HTTPS. It uses `Route` structs containing `Matcher` (path, header, query, method) and `Modifier` (header injection, redirection, path stripping) components to direct traffic. The proxy automatically strips configured path prefixes from upstream requests while preserving segment boundaries.

TLS handling is flexible: static certificates are provided via `AddHostWithTLS`, while dynamic issuance is handled by `AddHostWithACME`. The latter probes the host's public IP to ensure ACME HTTP-01 reachability before binding port 80, then waits for the certificate in the background before enabling the TLS listener. The system supports round-robin DNS by requiring a majority of resolved IPs to pass the probe.

HTTP/2 is enabled by default for TLS listeners, and HTTP/3 (QUIC) is served on a separate UDP listener for public addresses. Internal WireGuard routes remain on HTTP/1.1. Route selection prioritizes the longest matching path prefix to prevent catch-all routes from shadowing specific ones.