<!-- docdaemon ts:2026-10-19T23:25:53Z hash:abdd24e1dea18293 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains Ginkgo-based integration tests for the `meter` package, verifying request/response size tracking and HTTP interface compatibility.

The test suite validates `meter.MeteredServer` behavior by spinning up local listeners on random ports. It ensures that `MakeMeteredHTTPHandler` correctly exposes `BytesRx()` and `BytesTx()` metrics after processing requests. Specific cases confirm support for the `http.Hijacker` interface (allowing raw connection access) and the `http.Flusher` interface (enabling chunked responses), ensuring these standard interfaces remain functional when wrapped by the metering logic.