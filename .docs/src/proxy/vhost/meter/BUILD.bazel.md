<!-- docdaemon ts:2026-10-09T01:40:25Z hash:1e801c9384765a75 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This Bazel build file defines the Go library and test targets for the HTTP request metering subsystem within the proxy vhost module.

### Purpose
The file configures the `go_library` target named `meter`, which compiles the core implementation files `meter.go` and `meter_http3.go`. It exposes these sources under the import path `github.com/aquaduct-dev/weft/src/proxy/vhost/meter` with public visibility, allowing other packages in the repository to depend on this metering logic.

### Test Configuration
A corresponding `go_test` target named `meter_test` is defined to run the test suite. It includes:
- `meter_http2_test.go`
- `meter_http3_test.go`
- `meter_test.go`

The tests depend on the primary `:meter` library and external dependencies for testing frameworks (`ginkgo_v2`, `gomega`) and HTTP/3 support (`quic-go`). This setup ensures that both HTTP/2 and HTTP/3 metering behaviors are validated during the build process.