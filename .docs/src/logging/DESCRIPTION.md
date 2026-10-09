<!-- docdaemon ts:2026-10-09T01:41:55Z hash:2a1a78eebe63d8de model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `logging` package provides a centralized entry point for configuring application-wide structured logging using the `zerolog` library.

## Overview
This directory initializes and manages the global logger instance, ensuring consistent output formatting and severity levels across the entire application. It abstracts away the complexity of setting up console versus JSON outputs based on the deployment environment, allowing other components to simply import the package and begin logging immediately. By centralizing this configuration, the package guarantees that all log messages adhere to a uniform standard defined at startup.

## Deep Dive
### Initialization and Configuration
The core responsibility of this package is the `Init` function, which must be called early in the application lifecycle. This function accepts a `zerolog.Level` argument to define the minimum severity threshold for logs. Internally, it checks the `WEFT_ENV` environment variable to determine the output format. If the environment is not set to `"prod"`, the logger switches to a human-readable console format with RFC3339 timestamps written to `os.Stderr`. In production, it retains the default JSON formatter for machine-parseable logs. The function also calls `zerolog.SetGlobalLevel` to enforce the specified severity filter globally.

### Global Logger Management
By modifying the global `log` instance from `github.com/rs/zerolog/log`, this package ensures that any component importing the standard zerolog logger will automatically inherit the configured behavior. This eliminates the need for individual packages to manage their own logger instances or configuration logic, reducing boilerplate and potential inconsistencies in log output.

## Key Interfaces
- `func Init(level zerolog.Level)`: Configures the global logger with the specified level and environment-aware formatting.

## Dependencies
- `github.com/aquaduct-dev/weft/src/logging` (internal package reference)
- `github.com/rs/zerolog` (external structured logging library)
- `os` (standard library for stderr output)

## Subcomponents
- `BUILD.bazel`: Bazel build rules defining the Go library target.
- `logging.go`: Implementation of the initialization and global logger setup.