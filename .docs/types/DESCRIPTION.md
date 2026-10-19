<!-- docdaemon ts:2026-10-09T01:48:04Z hash:0bd90599427dd286 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `types` package defines the Go structs for API request and response payloads, serving as the contract layer for the HTTP API.

## Overview
This directory establishes the type-safe serialization contract between the server and clients. It groups related data structures into logical categories such as tunnel management, health checks, certificate metadata, and usage statistics. By decoupling business logic from wire format details, it ensures consistent JSON encoding and decoding across the application.

## Deep Dive
### Tunnel Management
`ConnectRequest` and `ConnectResponse` are the `/connect` payloads. The request's fields fall into three groups:
- Tunnel establishment: `ClientPublicKey`, `RemotePort`, `Protocol`, `Hostname` and `TunnelName`; the response returns the WireGuard side (`ServerPublicKey`, `ClientAddress`, `ServerWGPort`, `TunnelProxyPort`).
- Request routing and rewriting on the server's proxy for HTTP tunnels: `RemotePath` (prefix matched and stripped), `RemoteQuery` and `RemoteFragment` (matchers), and `RemoteModifiers` (header edits or `redirect`, taken from the local URL's fragment).
- Optional server-side TLS: when `CertificatePEM` and `PrivateKeyPEM` are set, the server terminates TLS for that tunnel's `Hostname` with this certificate instead of using ACME. They play no part in the client's control-API or WireGuard connection.

### Health & Status
`HealthcheckRequest` and `HealthcheckResponse` provide simple status reporting mechanisms. These lightweight structs enable quick verification of service availability and internal state consistency.

### Certificates
`CertInfo` and `CertificatesResponse` expose details about cached TLS certificates. This includes validity periods (`NotBefore`, `NotAfter`) and issuers, facilitating monitoring and renewal workflows for managed certificates.

### Usage Metrics
`TunnelUsage` and `UsageReport` aggregate byte-level traffic statistics (TX/RX) per tunnel instance. These metrics are essential for billing, quota enforcement, and performance analysis.

## Key Interfaces
- `ConnectRequest`: Payload for initiating a new tunnel connection.
- `ConnectResponse`: Result of a tunnel connection attempt.
- `HealthcheckRequest`: Input for health check endpoints.
- `HealthcheckResponse`: Output indicating service health status.
- `CertInfo`: Metadata for a single TLS certificate.
- `CertificatesResponse`: Collection of certificate metadata.
- `TunnelUsage`: Traffic statistics for a specific tunnel.
- `UsageReport`: Aggregated usage data for reporting.

## Dependencies
- Standard library `encoding/json` for serialization.
- Standard library `time` for date/time handling.

## Subcomponents
- `BUILD.bazel`: Bazel build configuration for the Go library.
- `types.go`: Definition of all API payload structs.