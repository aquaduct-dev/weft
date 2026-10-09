<!-- docdaemon ts:2026-10-09T01:40:30Z hash:04e45d59f056483b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements application-layer byte metering for HTTP/3 requests and responses where connection-level hooks are unavailable.

## Purpose
HTTP/3 over QUIC lacks a `net.Conn` per request, preventing the use of standard connection-level metering. This package wraps handlers to count Request (Rx) and Response (Tx) bytes at the application layer, ensuring accurate metrics despite QPACK compression and transport framing differences.

## Key Types

### `MeteredHTTPHandler.ServeHTTPMetered`
The entry point that instruments a request. It calculates initial header size, wraps the request body in a `countingReadCloser`, and passes control to the underlying handler via a `countingResponseWriter`. Upon completion, it aggregates total Rx/Tx bytes into atomic counters.

### `countingReadCloser`
Wraps `io.ReadCloser` to track bytes read from the request body. It increments an internal counter on every `Read` call.

### `countingResponseWriter`
Implements `http.ResponseWriter` to intercept status codes, headers, and body writes.
- **WriteHeader**: Captures header size when first called.
- **Write**: Tracks body bytes written. If headers haven't been explicitly written, it auto-emits a 200 OK and captures those headers.
- **Flush**: Delegates to the underlying writer if it supports `http.Flusher`, enabling streaming support.
- **txBytes**: Returns the sum of captured header and body bytes.

## Helper Functions
- `requestHeaderBytes`: Approximates the wire size of the request line and headers using HTTP/1-style framing logic.
- `responseHeaderBytes`: Approximates the wire size of the response status line and headers.