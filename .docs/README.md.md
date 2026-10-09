<!-- docdaemon ts:2026-10-09T01:40:51Z hash:babd92cb9095c04c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides installation instructions, usage examples, and architectural details for the Weft tunnelling proxy.

Weft is a Layer 4/Layer 7 proxy using WireGuard to expose local services securely. It supports TCP, UDP, HTTP, and HTTPS traffic with advanced routing features like path rewriting and header matching. The server manages ACME certificates via Let's Encrypt and enforces zero-trust authentication using encrypted challenge-response protocols. Clients connect via `weft tunnel` commands, while the server handles certificate issuance and peer management. Development relies on Bazel and includes pre-commit hooks for code quality.