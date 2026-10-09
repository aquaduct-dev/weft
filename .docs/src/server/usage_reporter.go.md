<!-- docdaemon ts:2026-10-09T01:40:48Z hash:ae34c7c8ae2e1acd model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements a periodic HTTP-based reporter that aggregates and sends tunnel usage statistics to an external endpoint.

### Purpose
The `HTTPUsageReporter` collects proxy traffic counters and peer information, marshals them into a JSON payload, and POSTs the data to a configured URL. It supports both periodic background reporting and on-demand synchronous reporting.

### Key Components

*   **`HTTPUsageReporter`**: The main struct holding configuration (URL, interval), dependency injection functions (`getCounters`, `getPeers`, `closing`), and an HTTP client.
*   **`NewHTTPUsageReporter`**: Constructor that initializes the reporter with a 10-second timeout for the HTTP client.
*   **`Start` / `Stop`**: Lifecycle methods. `Start` launches a goroutine using a ticker to call `ReportUsage` at the specified interval. `Stop` closes a channel to signal the goroutine to exit and waits for completion via `sync.WaitGroup`.
*   **`ReportUsage`**: Core logic that gathers current state from injected functions. If `tunnels` is nil, it reports all active tunnels; otherwise, it filters by name. It handles JSON marshaling errors and HTTP response status codes, logging warnings for non-2xx responses.

### Integration
This component decouples usage tracking from the core proxy logic by accepting functional dependencies. It ensures graceful shutdown by checking the `closing` function before sending reports and properly cleaning up resources in `Stop`.