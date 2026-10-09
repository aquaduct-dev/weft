<!-- docdaemon ts:2026-10-09T01:40:28Z hash:883f61bca029734c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides deterministic unit tests for HTTP/3 byte metering and end-to-end QUIC connectivity.

### Purpose
It validates that `meter.MeteredHTTPHandler` correctly accounts for request and response bytes over the HTTP/3 protocol, ensuring both logical accounting and actual network transport work as expected.

### Key Functions
- **`TestServeHTTPMetered_CountsRequestAndResponse`**: A deterministic test using `httptest` to verify that `BytesRx()` and `BytesTx()` accurately reflect body sizes plus header overhead without requiring a live network connection.
- **`TestHTTP3_RoundTripAndMeters`**: An integration-style test that spins up a real `http3.Server` on a UDP socket. It performs an actual HTTP/3 GET request to confirm the server responds with HTTP/3 and that `BytesTotal()` reflects the transferred data.

### Context
These tests complement `meter_http2_test.go` by covering the QUIC-specific path. They rely on `selfSignedCert` (defined in the HTTP/2 test file) to establish TLS for the HTTP/3 server.