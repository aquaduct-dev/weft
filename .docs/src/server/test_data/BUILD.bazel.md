<!-- docdaemon ts:2026-10-09T01:40:44Z hash:9a5a092ea9c0316b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This Bazel build file exposes PEM-formatted TLS certificates and private keys as public files for use in server-side tests.

### Purpose
The `BUILD.bazel` file defines a package containing test fixtures required for secure communication testing. It makes the certificate (`cert.pem`) and private key (`key.pem`) available to other targets within the repository.

### Key Components
- **`package(default_visibility = ["//visibility:public"])`**: Sets the default visibility of all targets in this package to public, allowing any target in the repository to depend on or access these files without explicit permission declarations.
- **`exports_files([...])`**: Declares `cert.pem` and `key.pem` as exportable files. This allows other rules (such as `copy_file` or custom test runners) to reference these assets directly via their labels (e.g., `@repo//src/server/test_data:cert.pem`).

### Integration
These files are typically consumed by integration or unit tests that verify TLS handshake behavior, certificate validation, or key usage. By exporting them explicitly, the build system ensures they are included in the output tree and accessible during test execution.