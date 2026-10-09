<!-- docdaemon ts:2026-10-09T01:40:20Z hash:e850bdbbf085fcb8 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file initializes the global zerolog logger with console formatting and severity levels based on environment configuration.

## Purpose
The `logging` package provides a centralized entry point for configuring application-wide logging behavior. It ensures that all components using the `github.com/rs/zerolog/log` package share a consistent output format and log level.

## Functions

### `Init(level zerolog.Level)`
Configures the global logger instance. This function should be called early in the application lifecycle, typically during startup or initialization.

1. **Output Formatting**: Checks the `WEFT_ENV` environment variable. If it is not set to `"prod"`, the logger is configured to output human-readable console logs to `os.Stderr` using RFC3339 timestamps. In production environments, the default JSON formatter remains active.
2. **Global Level**: Sets the minimum log level for all zerolog instances via `zerolog.SetGlobalLevel`. Any logs below this threshold will be discarded.

## Usage
Import this package and call `logging.Init()` before any other code attempts to log messages. Ensure the desired log level (e.g., `zerolog.DebugLevel`, `zerolog.InfoLevel`) is passed as an argument.