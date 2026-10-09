<!-- docdaemon ts:2026-10-09T01:40:07Z hash:9971904cb1849b14 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel test target for the server package, aggregating connectivity, eviction, and tunnel tests.

### Purpose
The `src/BUILD.bazel` file configures the Go test suite for the `src` directory using the `rules_go` extension. It creates a single test binary (`src_test`) that runs all integration and unit tests related to the server infrastructure.

### Key Components
- **Test Sources**: Includes four specific test files:
  - `server_connectivity_test.go`: Validates network connectivity.
  - `server_eviction_repro_test.go`: Reproduces server eviction scenarios.
  - `server_tunnel_suite_test.go`: Sets up the Ginkgo test suite.
  - `server_tunnel_test.go`: Tests tunnel functionality.
- **Dependencies**: Links against internal packages (`auth`, `client`, `crypto`, `proxy`, `server`, `tunnel`, `types`, `wireguard`) and external testing libraries (`ginkgo`, `gomega`, `wgctrl`).

### Integration
This build rule is part of the larger Bazel workspace structure, enabling developers to run the full server test suite via `bazel test //src:...`.