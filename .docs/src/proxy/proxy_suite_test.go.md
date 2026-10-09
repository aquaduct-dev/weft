<!-- docdaemon ts:2026-10-09T01:40:20Z hash:cf09119c40932517 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file initializes the Ginkgo test suite for the `proxy` package.

It defines the entry point for running all proxy-related tests using the Ginkgo and Gomega frameworks. The `TestProxy` function registers the failure handler and executes the test specs, serving as the standard bootstrap for Go integration tests in this module.