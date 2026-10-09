<!-- docdaemon ts:2026-10-09T01:40:11Z hash:9758d3ae4d1aec5c model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the TLS fingerprint pinning logic in the `auth` package.

It verifies that `loginTLSConfig()` correctly enforces certificate pinning via `PinnedFingerprint`. The tests cover the happy path where a matching SHA-256 leaf certificate hash allows the connection, and the negative path where a mismatched hash causes the handshake to fail with a "fingerprint mismatch" error. It also ensures the configuration tolerates the optional `sha256:` prefix and falls back to legacy `InsecureSkipVerify` behavior when no pin is set.