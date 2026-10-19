<!-- docdaemon ts:2026-10-19T23:25:50Z hash:4ab9f78d46060bb8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `logging.Init` function, verifying environment-based logger configuration and level enforcement.

### Purpose
The tests ensure `Init` correctly switches between human-readable console output (non-prod) and JSON logging (prod), while applying the requested global log level in both scenarios.

### Key Functions

*   **`saveGlobals`**: A helper that snapshots `log.Logger`, `zerolog.GlobalLevel()`, and `os.Stderr`. It restores these values via `t.Cleanup` to prevent test state leakage.
*   **`TestInitConsoleOutsideProd`**: Verifies behavior when `WEFT_ENV` is empty or `"dev"`. It redirects `os.Stderr` to a pipe to capture output, confirming:
    *   The global level is set correctly.
    *   Output is human-readable (contains "INF", not JSON).
    *   Messages below the configured level are suppressed.
*   **`TestInitKeepsJSONInProd`**: Verifies behavior when `WEFT_ENV` is `"prod"`. It replaces the logger with a buffer writer to confirm:
    *   The existing JSON logger format is preserved.
    *   The global level is applied (suppressing info messages when set to warn).