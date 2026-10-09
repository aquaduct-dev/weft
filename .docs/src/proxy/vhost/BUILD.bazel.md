<!-- docdaemon ts:2026-10-09T01:40:22Z hash:7ec8875589958a1e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This Bazel build file defines the Go library and test targets for the virtual host proxying module.

It compiles `vhost.go`, `acme_redirect.go`, and `errorlog.go` into a public library named `vhost`. The library depends on ACME automation, internal utilities, metrics, and QUIC/HTTP3 support.

The associated test target `vhost_test` embeds the main library and includes tests for certificates, path prefixes, probes, and race conditions using Ginkgo and Gomega.