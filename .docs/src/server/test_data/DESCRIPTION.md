<!-- docdaemon ts:2026-10-09T01:41:28Z hash:1c156c75ba68a404 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory contains PEM-formatted TLS certificates and private keys used for server-side testing.

## Overview
The `test_data` directory provides essential cryptographic fixtures required to validate secure communication protocols within the application's test suite. By exposing these assets as public files, the build system ensures that integration and unit tests can reliably access the necessary credentials without hardcoding sensitive values in source code. This separation of concerns allows tests to verify TLS handshake behaviors, certificate validation logic, and key usage patterns against known-good data.

## Deep Dive
### Test Fixtures
The primary responsibility of this package is to serve as a repository for static test artifacts. It exports `cert.pem` and `key.pem`, which are standard PEM-encoded X.509 certificates and RSA/EC private keys respectively. These files are not meant for production use but rather to simulate real-world TLS environments during automated testing.

### Build Visibility
The `BUILD.bazel` file configures the package with `default_visibility = ["//visibility:public"]`. This configuration removes access restrictions, allowing any target in the repository to depend on these files. The `exports_files` rule explicitly declares these assets as exportable, ensuring they are included in the output tree and accessible via labels like `@repo//src/server/test_data:cert.pem`. This simplifies dependency management for test rules that need to copy or reference these files directly.

## Key Interfaces
- None (files only)

## Dependencies
- Bazel build system

## Subcomponents
- BUILD.bazel
- cert.pem
- key.pem