<!-- docdaemon ts:2026-10-09T01:40:32Z hash:ceabf94d7254ea4e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a multi-host reverse proxy with dynamic TLS termination, ACME automation, and HTTP/3 support.

### Core Types
- **`VHostProxy`**: Manages routes per hostname, handling TCP (HTTP/1.1 & 2) and UDP (HTTP/3) listeners.
- **`VHostProxyManager`**: Orchestrates multiple proxies, ACME certificate issuance (`autocert`), and peer redirect challenges.
- **`Route`**: Combines matchers (path, header, query, method) and modifiers (redirects, header injection).

### Key Functions
- **`AddHost` / `AddHostWithTLS`**: Register static HTTPS or HTTP routes with explicit certificates.
- **`AddHostWithACME`**: Registers a host for automatic Let's Encrypt issuance, probing reachability first.
- **`ServeHTTP`**: Routes incoming requests to the correct handler based on Host header and path specificity.
- **`CanPassACMEChallenge`**: Validates DNS resolution and firewall accessibility for ACME HTTP-01 challenges.

### Integration
The proxy sits at the network edge, terminating TLS and forwarding traffic to upstream services via `httputil.ReverseProxy`. It integrates with WireGuard devices for internal routing and uses `meter` for request instrumentation.