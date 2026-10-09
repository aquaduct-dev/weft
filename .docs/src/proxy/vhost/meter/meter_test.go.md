<!-- docdaemon ts:2026-10-09T01:40:30Z hash:f37cba5ec4180320 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains Ginkgo-based integration tests for the `meter` package, verifying request/response size tracking and HTTP interface compatibility.

### Purpose
The test suite validates the behavior of `MeteredServer` and `MakeMeteredHTTPHandler`. It ensures that byte counts are accurately recorded for both incoming requests and outgoing responses, and that the metering layer correctly wraps standard `http.ResponseWriter` interfaces like `Hijacker` and `Flusher`.

### Key Components
- **`testHandler`**: A helper struct used in specific scenarios to capture `MeteredRequest` data and bytes written via a channel, allowing asynchronous verification within the handler execution context.
- **`Describe("MeteredServer")`**: The main test block containing three specifications:
  - **"meters request and response sizes correctly"**: Verifies that `BytesRx()` and `BytesTx()` return accurate byte counts by comparing them against `httputil.DumpRequestOut` and the actual response body length.
  - **"supports http.Hijacker interface"**: Confirms that underlying connections can be hijacked for raw TCP communication without breaking the metering wrapper.
  - **"supports http.Flusher interface"**: Ensures that partial writes and flushing work correctly while maintaining accurate byte accounting.