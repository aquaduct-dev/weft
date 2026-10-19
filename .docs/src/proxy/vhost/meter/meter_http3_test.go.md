<!-- docdaemon ts:2026-10-19T23:25:52Z hash:1d29590e85263e99 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the HTTP/3 metering path, verifying byte accounting and protocol compliance.

It validates `meter.MeteredHTTPHandler` by testing standard request/response counting and ensuring that streaming flushes do not alter byte totals. The `TestHTTP3_RoundTripAndMeters` function performs an end-to-end QUIC round-trip to confirm that HTTP/3 traffic is correctly served and metered, reusing TLS certificates from the HTTP/2 test suite.