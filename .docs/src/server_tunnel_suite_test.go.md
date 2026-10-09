<!-- docdaemon ts:2026-10-09T01:40:51Z hash:3d04979b122d426a model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file bootstraps the Ginkgo test suite for the server tunnel functionality.

It serves as the entry point for running Ginkgo tests within this package. By defining the `TestServerTunnel` function, it allows standard Go testing tools and Bazel to execute the Ginkgo `Describe` blocks defined in `server_tunnel_ginkgo_test.go`.

### Key Components

*   **Package Declaration**: Declares `package server_test`, grouping these integration tests with other server-related tests.
*   **Imports**:
    *   `testing`: Provides the standard Go test runner interface.
    *   `github.com/onsi/ginkgo/v2`: Imported via dot import (`. "..."`) to access Ginkgo functions like `RunSpecs` and `Fail` directly without prefixing.
    *   `github.com/onsi/gomega`: Imported via dot import to access Gomega matchers and utilities.
*   **`TestServerTunnel(t *testing.T)`**: The main test function required by Go's `testing` package. It initializes the Ginkgo runtime by registering a fail handler and executing all specs in the "Server + Tunnel Suite".

### Integration
This file enables the modular test structure where specific scenarios are written in separate files (e.g., `*_ginkgo_test.go`). Without this bootstrap file, the Ginkgo specs would not be discovered or executed by `go test`.