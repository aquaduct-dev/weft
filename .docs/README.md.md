<!-- docdaemon ts:2026-10-15T20:41:50Z hash:7c0f4404e64e4609 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides installation instructions, usage examples, and architectural details for the Weft tunnelling proxy.

Weft is a Layer 4/Layer 7 tunnelling proxy using WireGuard to expose local resources via public IPs. It consists of a server component that manages connections and ACME certificates, and a tunnel client that forwards traffic from local services to the server. The system supports complex HTTP routing rules, including path rewriting, header modification, and query parameter matching. Security is enforced through a zero-trust challenge-response protocol that securely exchanges TLS certificates and JWTs without exposing secrets in transit.