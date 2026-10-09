<!-- docdaemon ts:2026-10-09T01:41:12Z hash:168acc73d89c4bd7 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements HTTP request and response metering for HTTP/1.1, HTTP/2, and HTTP/3 protocols.

## Overview
The `meter` package provides infrastructure to measure network traffic volume (bytes transmitted/received) for HTTP servers. It supports standard HTTP/1.1 and HTTP/2 over TLS, ensuring accurate counting even when connections are wrapped by TLS layers or multiplexed. For HTTP/3, it adapts to the lack of per-request connection hooks by instrumenting at the application layer.

## Deep Dive
### Connection-Level Metering (HTTP/1.1 & HTTP/2)
For HTTP/1.1 and HTTP/2, metering relies on wrapping `net.Conn`. The `countingConn` type increments atomic counters on every `Read` and `Write` operation. `MeteredServer` injects this logic via `ConnContext` and listener wrapping. `ServeTLSCounted` places the counter beneath the TLS layer, allowing HTTP/2 negotiation while measuring on-wire bytes accurately.

### Application-Layer Metering (HTTP/3)
HTTP/3 over QUIC lacks a `net.Conn` per request, preventing standard connection-level metering. This module wraps handlers to count Request (Rx) and Response (Tx) bytes at the application layer. `countingResponseWriter` intercepts status codes, headers, and body writes, aggregating totals into atomic counters upon completion.

### Metrics Aggregation
Global metrics (`BytesTx`, `BytesRx`, `BytesTotal`) are tracked using a `sync.Map` for active connections. Per-request wrappers like `MeteredRequest` and `MeteredResponseWriter` expose total bytes read/written via `TotalSize()` and `BytesWritten()`, enabling granular monitoring alongside aggregate statistics.

## Key Interfaces
- `NewMeteredServer`: Creates an `http.Server` configured to extract connection counters from context.
- `MeteredHTTPHandler`: Adapter that tracks per-request metrics and aggregates them into global counters.
- `countingConn`: A `net.Conn` wrapper that increments atomic counters on I/O operations.
- `countingResponseWriter`: Implements `http.ResponseWriter` to intercept and track header/body writes.
- `asCountingConn`: Safely unwraps nested connections (e.g., through `*tls.Conn`) to retrieve the underlying `*countingConn`.

## Dependencies
- `github.com/aquaduct-dev/weft/src/proxy/vhost/meter` (internal import path)
- `ginkgo_v2`, `gomega` (testing frameworks)
- `quic-go` (HTTP/3 support)

## Subcomponents
- `BUILD.bazel`: Bazel build configuration for library and test targets.
- `meter.go`: Core implementation for HTTP/1.1 and HTTP/2 metering.
- `meter_http2_test.go`: Integration tests for HTTP/2 negotiation and ACME support.
- `meter_http3.go`: Application-layer metering for HTTP/3/QUIC.
- `meter_http3_test.go`: Unit and integration tests for HTTP/3 metering.
- `meter_test.go`: Ginkgo-based integration tests for general metering behavior.