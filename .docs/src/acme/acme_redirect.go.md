<!-- docdaemon ts:2026-10-09T01:40:09Z hash:843724ac577835a0 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements peer-to-peer coordination for ACME HTTP-01 challenge redirects in a weft cluster.

## Purpose
In DNS round-robin setups, the ACME validator may hit a node without the `keyAuth`. This package solves that by having nodes POST to peers to register a 301 redirect to the orderer. It ensures validation succeeds regardless of which IP the validator resolves.

## Trust Model
Authorization relies on verifying the sender's IP exists in the host's DNS records. TLS is used for transport only (`InsecureSkipVerify`); certificates are not validated as there is no shared trust root between nodes.

## Key Functions
*   **`RegisterRedirectsLoop`**: The core coordinator. It periodically queries DNS for the host's A-records (sorted descending) and attempts to POST `/acme-redirect` to each peer. If all higher peers fail, it falls back to becoming the "leader" (self).
*   **`PostACMERedirect`**: Sends the registration request to a specific peer address. Returns an error if the status code is non-successful.
*   **`LocalIPs` / `DescendingPeerIPs`**: Helper functions to enumerate local interfaces and resolve remote IPs, respectively. Used to determine leadership and target selection.

## Integration
Callers should invoke `RegisterRedirectsLoop` with a context to start the background task. Use `DefaultPeerPort` (9092) unless the deployment overrides the standard port.