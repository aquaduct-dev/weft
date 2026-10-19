<!-- docdaemon ts:2026-10-09T01:42:09Z hash:697aee4f73f69aca model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `client` package provides a Go library for programmatically managing Weft server tunnels and monitoring their health status.

## Overview
This directory contains the core client-side logic for interacting with the Weft administrative API. It handles authentication via JWTs, manages tunnel lifecycle operations such as listing and shutdown, and implements an adaptive health monitoring loop to ensure connectivity stability. The code ensures secure communication through TLS and robust error handling with exponential backoff.

## Deep Dive
### Client Initialization and Authentication
The `Client` struct encapsulates connection details, including the server URL and target tunnel name. Initialization in `NewClient` parses the URL, assigns default ports, and extracts credentials. Authentication is lazy; `ensureAuth` invokes the `auth` package to obtain a JWT scoped to either generic admin rights or a specific tunnel. This design minimizes overhead until an API call is required.

### Tunnel Management
Administrative actions are performed via HTTP POST requests. `ListTunnels` retrieves active tunnel metrics (TX/RX bytes) from the `/list` endpoint using the generic admin context. `Shutdown` targets a specific tunnel defined at initialization, sending a request to `/shutdown`. Both functions validate prerequisites, such as ensuring a tunnel name exists before attempting scoped shutdowns.

### Health Monitoring
`health_monitor.go` implements an adaptive loop that pings the `/healthcheck` endpoint. It uses `HealthMonitorConfig` to define intervals and failure thresholds. Transient errors trigger exponential backoff up to a maximum interval, while permanent failures (e.g., 401/404 or certificate issues) invoke the `OnFatal` callback. When the caller leaves `OnFatal` nil it defaults to `log.Fatal`, which exits the process to prevent silent degradation; tests and embedders can supply their own handler instead. This ensures immediate detection of critical service disruptions.

## Key Interfaces
- `NewClient(weftURLStr, tunnelName string)` initializes the client with URL parsing and credential extraction.
- `ListTunnels()` returns a map of active tunnel names to their `TunnelInfo` metrics.
- `Shutdown()` terminates the specific tunnel associated with the client instance.
- `NewHealthMonitor(config HealthMonitorConfig)` creates a monitor with configurable retry logic.
- `Start()` begins the blocking health check loop with dynamic interval adjustment.
- `Stop()` safely halts the health monitoring goroutine.

## Dependencies
- `//src/auth`: Provides JWT generation and login utilities.
- `//types`: Shares common type definitions used across the project.
- `@com_github_rs_zerolog//log`: Handles structured logging.
- `@com_github_golang_jwt_jwt_v4//:jwt`: Used for token validation in tests.
- `@com_github_stretchr_testify//assert`: Provides assertion helpers for testing.

## Subcomponents
- `BUILD.bazel`: Bazel build rules for compilation and testing.
- `client.go`: Core client library for tunnel management.
- `client_test.go`: Integration tests for client-server interactions.
- `health_monitor.go`: Adaptive health checking implementation.