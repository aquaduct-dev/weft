<!-- docdaemon ts:2026-10-19T23:25:59Z hash:32d830f23c537c56 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the `--retries` flag correctly triggers tunnel shutdown after consecutive healthcheck failures.

It orchestrates a test environment by starting a Weft server and a tunnel client configured with `--retries 3`. The server is then killed to simulate network failure, forcing the tunnel to detect healthcheck errors. The script waits for the tunnel process to exit within a 45-second window, ensuring it adheres to the adaptive retry logic (consecutive failures or sliding window). Finally, it validates the tunnel log for specific "Healthcheck failed" and shutdown messages to confirm the feature behaves as intended.