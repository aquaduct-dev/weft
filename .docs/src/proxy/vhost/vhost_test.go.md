<!-- docdaemon ts:2026-10-09T01:40:32Z hash:27c4b431ae6d2ee3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains Ginkgo integration tests for the VHost proxy routing, TLS management, and WireGuard-aware transport logic.

The test suite validates `VHostProxy` behavior, including forwarding requests to upstream hosts via `ServeHTTP`, handling dynamic TLS certificate injection with `AddHostWithTLS`, and ensuring correct 404 responses for unknown virtual hosts. It also verifies that ACME challenge routes are correctly prioritized over default handlers when both a specific host and an ACME host are registered.

Key types tested include:
- **VHostProxy**: Tests cover route resolution, HTTPS serving using generated certificates, and cache path configuration via `SetCertsCachePath`.
- **WGAwareRoundTripper**: Validates transport selection logic, ensuring it falls back to `http.DefaultTransport` when no WireGuard device is present, while still functioning correctly for non-WG targets.

These tests ensure the proxy manager correctly initializes routes, manages lifecycle hooks (like closing TLS listeners), and intercepts network connections for testing purposes without requiring actual external dependencies.