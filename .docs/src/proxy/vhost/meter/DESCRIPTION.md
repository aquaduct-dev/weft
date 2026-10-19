<!-- docdaemon ts:2026-10-19T23:26:24Z hash:88c9b2dce8c9f75f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package provides HTTP server components that accurately track byte traffic for both completed and in-flight requests across HTTP/1.1, HTTP/2, and HTTP/3 protocols.

## Overview
The `meter` module implements a transparent byte-metering layer for the proxy vhost system. It wraps standard HTTP servers to intercept connections and request/response streams, ensuring accurate usage reporting even during long-running transfers or streaming scenarios. By supporting multiple protocol versions, it allows the proxy to enforce consistent billing and monitoring policies regardless of client negotiation capabilities.

## Deep Dive
### Connection-Level Metering (HTTP/1.1 & HTTP/2)
For TCP-based protocols, the package uses a `countingListener` to wrap raw `net.Conn` objects with `countingConn`. This wrapper atomically tallies bytes read (`bytesRx`) and written (`bytesTx`). To support HTTP/2, `ServeTLSCounted` places the counter beneath TLS termination, allowing `net/http` to correctly negotiate ALPN protocols while still tracking encrypted traffic volume. The `asCountingConn` helper safely extracts counters from connection chains, using a bounded loop to prevent infinite recursion on cyclic wrappers.

### Application-Layer Metering (HTTP/3)
HTTP/3 over QUIC lacks per-request `net.Conn` hooks, so metering occurs at the application layer. `MeteredHTTPHandler.ServeHTTPMetered` instruments requests by wrapping the request body in a `countingReadCloser` and the response writer in a `countingResponseWriter`. This approach approximates header sizes and tracks body writes, aggregating totals into atomic counters upon completion. It supports streaming via `http.Flusher` delegation without altering byte counts.

### Active Request Tracking
To fix under-reporting for long-lived requests, the handler maintains an active connection map (`sync.Map`). Metrics now sum bytes from both completed requests and in-flight transfers, ensuring real-time accuracy.

## Key Interfaces
- `MeteredServer`: Wraps `http.Server` to provide TLS counting and context injection.
- `MeteredHTTPHandler`: Aggregates traffic metrics and exposes `BytesRx()`/`BytesTx()`.
- `countingConn`: Wraps `net.Conn` to track raw byte I/O.
- `countingResponseWriter`: Implements `http.ResponseWriter` to capture header and body sizes.
- `NewMeteredServer`: Constructor that injects connection context functions.

## Dependencies
- `github.com/quic-go/quic-go`: For HTTP/3 QUIC support.
- `ginkgo_v2`, `gomega`: Testing framework.
- Standard library: `net/http`, `crypto/tls`, `sync`, `io`.

## Subcomponents
- `meter.go`: Core implementation for HTTP/1.1 and HTTP/2 metering.
- `meter_http3.go`: Application-layer metering for HTTP/3.
- `BUILD.bazel`: Bazel build configuration for library and tests.
- `meter_test.go`: Integration tests for server and handler behavior.
- `meter_http2_test.go`: End-to-end tests for HTTP/2 negotiation and ACME support.
- `meter_http3_test.go`: Unit and round-trip tests for HTTP/3 metering.