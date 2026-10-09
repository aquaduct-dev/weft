<!-- docdaemon ts:2026-10-09T01:40:27Z hash:843335e9d27e17ed model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements HTTP request and response metering by wrapping connections, readers, and writers to track byte counts for both completed and in-flight requests.

### Purpose
The `meter` package provides infrastructure to measure network traffic volume (bytes transmitted/received) for HTTP servers. It supports standard HTTP/1.1 and HTTP/2 over TLS, ensuring accurate counting even when connections are wrapped by TLS layers or multiplexed.

### Key Types
- **`MeteredRequest` / `MeteredResponseWriter`**: Wrappers around standard `http.Request` and `http.ResponseWriter` that expose total bytes read/written via `TotalSize()` and `BytesWritten()`.
- **`countingConn`**: A `net.Conn` wrapper that increments atomic counters on every `Read` and `Write` operation.
- **`MeteredHTTPHandler`**: An adapter that tracks per-request metrics and aggregates them into global `BytesTx`, `BytesRx`, and `BytesTotal` counters using a `sync.Map` for active connections.
- **`MeteredServer`**: An `http.Server` extension that injects the metering logic via `ConnContext` and listener wrapping.

### Important Functions
- **`NewMeteredServer`**: Creates a server configured to extract connection counters from context.
- **`Serve`**: Wraps the underlying listener with `countingListener` to instrument plaintext connections.
- **`ServeTLSCounted`**: Instruments TLS connections by placing the counter beneath the TLS layer, allowing HTTP/2 negotiation while measuring on-wire bytes.
- **`asCountingConn`**: Safely unwraps nested connections (e.g., through `*tls.Conn`) to retrieve the underlying `*countingConn`.