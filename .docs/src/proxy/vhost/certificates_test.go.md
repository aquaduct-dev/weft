<!-- docdaemon ts:2026-10-09T01:40:24Z hash:fd14729d88662281 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `ListCertificates` method, verifying that it correctly parses cached certificates while ignoring non-certificate artifacts.

### Purpose
The test suite ensures the certificate cache loader behaves correctly in two scenarios:
1. **Filtering:** It skips files that are not valid certificates (e.g., ACME account keys or challenge tokens).
2. **Parsing:** It correctly extracts metadata (host, subject, issuer, expiry, DNS names) from self-signed PEM files.

### Key Functions
- **`writeSelfSignedCert`**: A helper that generates a temporary ECDSA key and self-signed X.509 certificate, writing them to a directory as a single PEM file. It returns the certificate's expiration time for validation.
- **`TestListCertificates`**: Creates a mix of valid certs and invalid artifacts, calls `ListCertificates`, and asserts that only valid certs are returned, sorted by host.
- **`TestListCertificatesMissingDir`**: Verifies that `ListCertificates` returns an empty list without error when the cache directory does not exist.