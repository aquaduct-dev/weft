<!-- docdaemon ts:2026-10-19T23:25:54Z hash:8431317937578c78 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This package provides HTTP server components that accurately track byte traffic for both completed and in-flight requests, supporting HTTP/1.1 and HTTP/2 over TLS.

The `MeteredServer` wraps `http.Server` to intercept connections via a `countingListener`, which replaces raw `net.Conn` objects with `countingConn` instances that atomically tally bytes read (`bytesRx`) and written (`bytesTx`). To support HTTP/2, `ServeTLSCounted` places the counter beneath TLS termination so `net/http` can negotiate ALPN protocols correctly.

Key types include:
- **`MeteredRequest` / `MeteredResponseWriter`**: Wrappers around standard HTTP types that expose total byte counts via `TotalSize()` and `BytesWritten()`.
- **`MeteredHTTPHandler`**: Aggregates traffic metrics by tracking active connections in a `sync.Map` alongside completed request totals, ensuring real-time accuracy even during long-running transfers.
- **`asCountingConn`**: Safely extracts the byte-counter from connection chains (e.g., unwrapping `*tls.Conn`) using a bounded loop to prevent infinite recursion on cyclic wrappers.

Configuration is handled via `NewMeteredServer`, which injects a `ConnContext` function to store per-connection counters in the request context for later retrieval by the handler.