<!-- docdaemon ts:2026-10-09T01:48:04Z hash:0bd90599427dd286 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `types` package defines the Go structs for API request and response payloads, serving as the contract layer for the HTTP API.

## Overview
This directory establishes the type-safe serialization contract between the server and clients. It groups related data structures into logical categories such as tunnel management, health checks, certificate metadata, and usage statistics. By decoupling business logic from wire format details, it ensures consistent JSON encoding and decoding across the application.

## Deep Dive
### Tunnel Management
`ConnectRequest` and `ConnectResponse` handle the lifecycle of establishing a tunnel. They support optional TLS termination via `CertificatePEM` and `PrivateKeyPEM`, allowing secure connection setup without exposing raw socket handling in higher-level handlers.

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