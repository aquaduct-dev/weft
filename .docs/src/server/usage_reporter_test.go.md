<!-- docdaemon ts:2026-10-09T01:40:48Z hash:2570507e928b3a13 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `HTTPUsageReporter` to verify periodic reporting, selective tunnel reporting, and various skip conditions.

The test suite validates the behavior of `NewHTTPUsageReporter` by mocking an HTTP server via `httptest.NewServer`. It ensures that usage data is correctly serialized and transmitted under different scenarios.

### Key Test Cases

*   **Periodic Reporting**: `TestHTTPUsageReporter_ReportsUsagePeriodically` verifies that the reporter automatically sends reports at the configured interval (10ms) and captures the correct tunnel structure.
*   **Selective Reporting**: `TestHTTPUsageReporter_ReportsSpecificTunnels` confirms that calling `ReportUsage` with a specific list of tunnel names filters the report to include only those tunnels.
*   **Empty URL Handling**: `TestHTTPUsageReporter_SkipsWhenURLEmpty` ensures that if the target URL is empty, the reporter does not invoke data collection getters or attempt to send requests.
*   **Closing State**: `TestHTTPUsageReporter_SkipsWhenClosing` checks that reports are suppressed when the system is in a closing state, preventing unnecessary network activity during shutdown.
*   **Empty Data Handling**: `TestHTTPUsageReporter_SkipsEmptyReport` verifies that no HTTP request is made if there are no counters or peers to report.