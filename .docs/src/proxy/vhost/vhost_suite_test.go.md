<!-- docdaemon ts:2026-10-09T01:40:30Z hash:a8ae83b5b6db93a4 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file initializes the Ginkgo test suite for the `vhost` package.

It sets up the entry point for running integration tests against the virtual host implementation. The `TestVhost` function registers the standard failure handler and triggers the execution of all defined specs within this suite. This ensures that the testing framework is correctly bootstrapped before any individual test cases are executed, providing a consistent environment for validating proxy virtual host behavior.