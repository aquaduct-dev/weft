<!-- docdaemon ts:2026-10-19T23:27:08Z hash:3f0ef532236123d2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `logging` package centralizes application-wide logging configuration using zerolog, adapting output formats based on the environment.

## Overview
This directory provides a unified entry point for configuring the global logger used throughout the Weft application. It ensures consistent log formatting and severity levels across all components by initializing the `github.com/rs/zerolog/log` instance during startup. The package automatically switches between human-readable console output for development and structured JSON logs for production environments.

## Deep Dive
### Initialization Strategy
The core logic resides in the `Init` function, which must be called early in the application lifecycle. It configures the global zerolog instance to ensure all subsequent log calls adhere to the specified settings. This approach prevents inconsistent logging behavior that might arise if individual packages configured their own loggers independently.

### Environment-Aware Formatting
The package inspects the `WEFT_ENV` environment variable to determine the output format. When `WEFT_ENV` is not set to `"prod"`, the logger outputs human-readable text to `os.Stderr` with RFC3339 timestamps. In production, it retains the default JSON formatter, ensuring machine-parseable logs for aggregation systems. This distinction supports developer experience while maintaining operational efficiency in production.

### Level Enforcement
Regardless of the format, `Init` sets the global minimum log level via `zerolog.SetGlobalLevel`. Any messages below this threshold are discarded immediately. This allows operators to control verbosity globally without modifying code in dependent packages. Tests verify that both console and JSON modes correctly respect these level constraints.

## Key Interfaces
- `Init(level zerolog.Level)`: Configures the global logger with the specified severity level and environment-appropriate formatting.

## Dependencies
- `github.com/rs/zerolog`: Provides the underlying structured logging engine.
- `os`: Used for accessing standard error streams.

## Subcomponents
- `logging.go`: Core implementation of the initialization logic.
- `logging_test.go`: Unit tests for environment-based configuration and level enforcement.
- `BUILD.bazel`: Bazel build targets for the library and its tests.