<!-- docdaemon ts:2026-11-12T09:10:28Z hash:c5ef15147e5d73df model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build targets for the ACME package, which manages TLS certificate acquisition and HTTP-01 challenge validation across a cluster of bastion nodes.

The `go_library` target compiles the core logic for interacting with Let's Encrypt via `golang.org/x/crypto/acme`. It includes `challenge_proxy.go` to handle peer-to-peer challenge forwarding, ensuring that when round-robin DNS directs a CA validator to a node other than the one holding the order, the challenge is proxied rather than redirected (which CAs reject). The `http01_only.go` component forces HTTP-01 validation exclusively, preventing `tls-alpn-01` failures caused by multiple nodes attempting simultaneous authorizations on port 443.

The `fresh_lookup.go` module addresses DNS caching issues where NXDOMAIN responses from new hosts block certificate issuance by resolving queries directly against zone nameservers instead of relying on the system resolver.

The `go_test` target uses Ginkgo/Gomega to verify these behaviors, including leader election fallbacks and peer connectivity checks. Dependencies include `zerolog` for structured event logging of certificate lifecycle events (cache hits, issuance success/failure) to aid operator auditing.