<!-- docdaemon ts:2026-10-15T20:43:08Z hash:4605f7426f0675fd model:openrouter/qwen/qwen3.7-flash -->
# Test Suite

## TL;DR
This directory contains the integration test suite for the `weft` tunneling application, validating core features like TCP/UDP proxying, HTTPS tunneling, and billing accuracy.

## Overview
The tests ensure end-to-end reliability of the Weft CLI by orchestrating mock servers, the Weft daemon, and client tunnels in isolated environments. They cover protocol-specific behaviors (HTTP, HTTPS, UDP), security mechanisms (TLS, MITM resistance), and operational logic (retries, graceful shutdown). The suite is designed to run against compiled binaries or Bazel-built targets, providing comprehensive coverage of the application's networking stack.

## Deep Dive
### Protocol Support
Tests verify correct forwarding for TCP (`test_tcp_proxy.sh`, `test_tcp_tunnel.sh`), UDP (`test_udp_proxy.sh`, `test_udp_tunnel.sh`), and HTTP/HTTPS traffic. HTTPS testing includes static TLS certificates (`test_https_proxy_static_tls.sh`) and self-signed certificate generation for tunnel endpoints (`test_https_tunnel.sh`).

### Feature Validation
Specific features are tested via dedicated scripts: header modification (`test_header_modifiers.sh`), path rewriting (`test_path_rewriting.sh`), query parameter matching (`test_matchers_rewriting.sh`), and HTTP redirects (`test_redirects.sh`). Security is validated through MITM rejection (`test_mitm.sh`) and secret enforcement (`test_secret_enforced.sh`).

### Reliability & Billing
The suite checks resilience by simulating server crashes (`test_retries.sh`) and process restarts (`test_tunnel_graceful_shutdown.sh`). It also ensures accurate usage reporting for single, multi-tunnel, and interrupted connections (`test_billing_reporting*.sh`), verifying that byte counts and metadata are correctly logged without duplication.

## Key Interfaces
- `lib.sh`: Shared Bash utilities for port allocation, process management, and cleanup.
- `BUILD.bazel`: Bazel targets defining the test execution environment and dependencies.

## Dependencies
- Python 3 (for mock HTTP/UDP servers)
- `curl` (for HTTP verification)
- `nc` / netcat (for UDP verification)
- `openssl` (for MITM simulation and cert generation)
- `weft` binary (compiled target under test)

## Subcomponents
- `lib.sh`
- `test_tcp_proxy.sh`
- `test_tcp_tunnel.sh`
- `test_udp_proxy.sh`
- `test_udp_tunnel.sh`
- `test_http_default_port.sh`
- `test_https_proxy_static_tls.sh`
- `test_https_tunnel.sh`
- `test_header_modifiers.sh`
- `test_path_rewriting.sh`
- `test_matchers_rewriting.sh`
- `test_redirects.sh`
- `test_mitm.sh`
- `test_secret_enforced.sh`
- `test_retries.sh`