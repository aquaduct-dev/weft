<!-- docdaemon ts:2026-10-09T01:41:05Z hash:5823116accf12341 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Go structs for API request and response payloads, including tunnel configuration, health checks, certificate metadata, and usage statistics.

The `types` package serves as the contract layer for the HTTP API, ensuring type-safe serialization of JSON bodies. It groups related data structures into logical categories:

*   **Tunnel Management**: `ConnectRequest` and `ConnectResponse` carry tunnel establishment (keys, port, protocol, hostname, tunnel name; WireGuard addresses and ports in the response). `ConnectRequest` also carries HTTP routing and rewriting for the server's proxy (`RemotePath`, `RemoteQuery`, `RemoteFragment`, `RemoteModifiers`) and an optional `CertificatePEM`/`PrivateKeyPEM` pair the server uses to terminate TLS for that tunnel's `Hostname`.
*   **Health & Status**: `HealthcheckRequest` and `HealthcheckResponse` provide simple status reporting mechanisms.
*   **Certificates**: `CertInfo` and `CertificatesResponse` expose details about cached TLS certificates, such as validity periods (`NotBefore`, `NotAfter`) and issuers.
*   **Usage Metrics**: `TunnelUsage` and `UsageReport` aggregate byte-level traffic statistics (TX/RX) per tunnel instance.

These types are used by the server's HTTP handlers to decode incoming requests and encode responses, decoupling business logic from wire format details.