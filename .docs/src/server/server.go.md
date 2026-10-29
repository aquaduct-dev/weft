<!-- docdaemon ts:2026-10-29T21:04:48Z hash:7e98621852fbdaad model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file initializes and configures the Weft control plane HTTP server, including TLS setup, authentication middleware, and background lifecycle workers.

`Server` struct holds the HTTP listener, tunnel state store, dataplane interface, and secrets. `NewServer` bootstraps the server by generating a self-signed TLS certificate (with SHA-256 fingerprint pinning for MITM protection), initializing the in-memory tunnel store, and starting the `Janitor` and `UsageReporter` background goroutines. It registers JWT-gated routes (`/connect`, `/healthcheck`, etc.) alongside unauthenticated endpoints (`/login`, `/version`).

`CreateDevice` provisions a userspace WireGuard device with a generated private key and returns the actual listen port. The server enforces security via `ConnectionSecret`-based challenge-response login and optional client-side certificate fingerprint pinning.