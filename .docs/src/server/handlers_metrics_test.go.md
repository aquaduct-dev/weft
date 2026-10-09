<!-- docdaemon ts:2026-10-09T01:40:39Z hash:b545a6f64212f023 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the metrics HTTP handler, focusing on authentication security and Prometheus exposition format integrity.

### Purpose
The tests verify that `MetricsHandler` correctly enforces Basic Authentication using a connection secret and safely escapes user-supplied data in Prometheus labels to prevent injection attacks.

### Key Tests
- **`TestMetricsHandler_AuthRejectsWrongSecret`**: Ensures any deviation from the correct secret (empty, partial, or extended) results in a `401 Unauthorized` response, confirming constant-time comparison behavior.
- **`TestMetricsHandler_AuthAcceptsCorrectSecret`**: Validates the happy path where the correct secret yields a `200 OK` response.
- **`TestPromQuote`**: Unit tests the internal `promQuote` helper function to ensure special characters (quotes, backslashes, newlines) are properly escaped for Prometheus label values.
- **`TestMetricsHandler_EscapesUserInput`**: Integration test verifying that malicious input in `ProxiedUpstream` and `DstURL` fields is sanitized. It confirms that injected metric names do not appear as top-level series and that control characters are escaped within label values.