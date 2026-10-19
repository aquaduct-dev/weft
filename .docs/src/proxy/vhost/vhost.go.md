<!-- docdaemon ts:2026-10-15T20:41:53Z hash:3cc0bba0da0c5ce4 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a name-based virtual host reverse proxy with support for HTTP/2, HTTP/3, and automatic TLS certificate management via ACME.

### Core Components
- **VHostProxy**: Manages routes per hostname, handling request matching (`PathMatcher`, `HeaderMatcher`) and modification (`RedirectModifier`, `PathPrefixModifier`). It supports both plain HTTP and TLS termination.
- **VHostProxyManager**: Orchestrates multiple proxies, manages the ACME certificate cache, and handles peer-to-peer challenge redirections for distributed ACME issuance.
- **WGAwareRoundTripper**: A custom `http.RoundTripper` that routes requests to internal WireGuard addresses (`10.1.*`) through a userspace network stack when constructed with a non-nil WireGuard device (otherwise it uses `http.DefaultTransport`), with failure tracking to trigger tunnel cleanup on sustained dial errors.

### Key Functions
- **AddHost/AddHostWithTLS/AddHostWithACME**: Register reverse proxy routes. `AddHostWithACME` binds port 80, probes reachability, and asynchronously fetches certificates before enabling HTTPS.
- **Start**: Initializes TCP listeners (and optional UDP for HTTP/3). Configures ALPN negotiation for h2/h3 and sets up TLS `GetCertificate` logic to serve cached or ACME-managed certs.
- **CanPassACMEChallenge**: Validates DNS resolution and probes public IPv4 endpoints for ACME HTTP-01 readiness, supporting round-robin DNS with a configurable success threshold.
- **ServeHTTP/findRoute**: Dispatches incoming requests to the most specific matching route based on path prefix length, adhering to Gateway-API precedence rules.