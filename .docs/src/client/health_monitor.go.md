<!-- docdaemon ts:2026-10-09T01:40:17Z hash:a304dd5dbef9a494 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements an adaptive health monitoring loop that adjusts check frequency based on server response and terminates the process on permanent failures.

### Purpose
`HealthMonitor` performs periodic POST requests to a Weft server’s `/healthcheck` endpoint. It uses exponential backoff for transient errors and immediate termination for permanent issues (e.g., certificate errors or 401/404 responses).

### Key Types
- **`HealthMonitorConfig`**: Defines HTTP client, URLs, timing intervals (`BaseInterval`, `RetryInterval`, `MaxInterval`), failure thresholds (`MaxRetries`), and sliding window duration. Includes `OnFatal` for testable shutdown logic.
- **`HealthMonitor`**: The struct managing state, including mutex protection, ticker control, and failure tracking arrays.

### Important Functions
- **`NewHealthMonitor`**: Initializes the monitor with sensible defaults for zero-valued config fields.
- **`Start`**: Blocks in a loop, ticking at `currentInterval`. Resets the ticker dynamically as intervals change. Exits on `Stop()` signal or fatal error.
- **`Stop`**: Closes the `done` channel to halt the `Start` loop safely.
- **`doHealthcheck`**: Executes the request. Classifies errors into permanent (fatal) or transient. Updates `consecutiveFailures` and `recentFailures` for sliding window logic. Adjusts `currentInterval` using backoff multiplier up to `MaxInterval`.

### Integration
Used by tunnel components to ensure connectivity. Permanent failures call `OnFatal`, which defaults to `log.Fatal` (exiting the process to prevent silent degradation) when the caller does not supply one.