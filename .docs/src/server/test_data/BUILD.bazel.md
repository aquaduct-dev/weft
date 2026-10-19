<!-- docdaemon ts:2026-10-09T01:40:44Z hash:9a5a092ea9c0316b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This Bazel build file exports labels for two TLS fixture files, `cert.pem` and `key.pem`, that are not checked in.

### Purpose
The package was set up to share server test fixtures. It declares the certificate (`cert.pem`) and private key (`key.pem`) as files other targets may reference, but neither file exists in the repository and nothing currently references them.

### Key Components
- **`package(default_visibility = ["//visibility:public"])`**: Lets any target in the repository reference the exported files.
- **`exports_files([...])`**: Declares `cert.pem` and `key.pem` as labels (e.g. `//src/server/test_data:cert.pem`). Referencing one today fails, since the file is missing.

### Integration
No test uses these labels; tests that need TLS material generate it at runtime with `crypto.GenerateCert`.
