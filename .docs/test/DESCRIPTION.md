<!-- docdaemon ts:2026-10-09T01:48:06Z hash:5a1bce38c95d876b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory contains the integration test suite for the Weft tunneling application, validating core features through shell-based end-to-end scenarios.

## Overview
The `test` directory houses a comprehensive collection of Bash scripts designed to verify the correctness, security, and reliability of the Weft binary. These tests simulate real-world usage by orchestrating multiple background processes, including Python mock servers and the Weft daemon itself, to ensure proper traffic forwarding and state management. The suite covers protocol tunnels, proxy modes, billing accuracy, and security constraints, providing a robust regression check for the codebase.

## Deep Dive
### Protocol Tunnels and Proxies
Core functionality is validated through `test_tcp_tunnel.sh`, `test_udp_tunnel.sh`, and their corresponding proxy variants (`test_tcp_proxy.sh`, `test_udp_proxy.sh`). These scripts establish connections between local Python mock servers and remote endpoints, verifying that HTTP and UDP payloads are correctly forwarded. Additional tests like `test_https_tunnel.sh` ensure TLS termination works with self-signed certificates, while `test_http_default_port.sh` confirms standard port handling.

### Feature Validation
Advanced routing logic is tested in `test_path_rewriting.sh` and `test_matchers_rewriting.sh`, which verify URL prefix stripping and query parameter filtering. Header manipulation is checked in `test_header_modifiers.sh`, ensuring rules for adding, deleting, or setting headers are applied correctly. Redirects are validated via `test_redirects.sh`, confirming 302 responses point to the correct targets. Retry logic and graceful shutdown behaviors are covered by `test_retries.sh` and `test_tunnel_graceful_shutdown.sh`.

### Security and Reliability
Security tests include `test_mitm.sh`, which ensures MITM proxies cannot intercept encrypted traffic, and `test_secret_enforced.sh`, which validates connection secret authentication. Health checks are verified in `test_probe.sh`. Reliability is further tested in `test_multi_route_cleanup.sh` and `test_multi_tunnel.sh`, ensuring that multiple concurrent tunnels operate independently without resource leaks or cross-contamination during partial teardowns.

### Billing and Reporting
Billing accuracy is the focus of several scripts: `test_billing_reporting.sh` checks metadata inclusion, `test_billing_reporting_interrupted.sh` verifies byte counts on early disconnects, `test_billing_reporting_multi_tunnel.sh` ensures metrics for concurrent tunnels are distinct, and `test_billing_reporting_no_double_count.sh` prevents data duplication in logs.

## Key Interfaces
- `lib.sh`: Shared library providing utilities for port allocation, process management, and cleanup traps.
- `BUILD.bazel`: Bazel build configuration defining `sh_library` and individual `sh_test` targets.

## Dependencies
- `weft` binary (compiled from source)
- Python 3 (for mock HTTP/UDP servers)
- `curl` (for HTTP verification)
- `nc` / netcat (for UDP verification)
- `openssl` (for certificate generation and MITM simulation)

## Subcomponents
- `lib.sh`
- `test_billing_reporting.sh`
- `test_billing_reporting_interrupted.sh`
- `test_billing_reporting_multi_tunnel.sh`
- `test_billing_reporting_no_double_count.sh`
- `test_header_modifiers.sh`
- `test_http_default_port.sh`
- `test_https_tunnel.sh`
- `test_matchers_rewriting.sh`
- `test_mitm.sh`
- `test_multi_route_cleanup.sh`
- `test_multi_tunnel.sh`
- `test_path_rewriting.sh`
- `test_probe.sh`
- `test_redirects.sh`
- `test_retries.sh`
- `test_secret_enforced.sh`
- `test_tcp_proxy.sh`
- `test_tcp_tunnel.sh`
- `test_tunnel_graceful_shutdown.sh`
- `test_udp_proxy.sh`
- `test_udp_tunnel.sh`