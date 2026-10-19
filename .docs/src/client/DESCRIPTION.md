<!-- docdaemon ts:2026-10-19T23:27:13Z hash:ecf968003f665148 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory provides the Go client library for managing Weft server tunnels and monitoring their health status.

## Overview
The `client` package exposes programmatic access to administrative HTTP endpoints, allowing external tools to list active tunnels or trigger shutdowns. It handles authentication via JWTs obtained through a challenge-response flow and manages TLS connections securely. Additionally, it includes an adaptive health monitor that ensures connectivity by adjusting retry intervals based on server responses.

## Deep Dive
### Client Initialization and Authentication
The `Client` struct encapsulates connection details, including the server URL and tunnel scope. The `NewClient` function parses the URL, assigns a default port if missing, and extracts the connection secret from user info. Authentication is lazy; `ensureAuth` calls the `auth` package to obtain a JWT scoped to either a specific tunnel or generic admin operations. This design prevents unnecessary network calls until an action is required.

### Tunnel Management
Administrative actions are performed via POST requests to `/list` and `/shutdown`. `ListTunnels` retrieves metrics for all active tunnels using the generic admin context. `Shutdown` targets a specific tunnel defined at initialization. A critical safety check prevents accidental global shutdowns: if no tunnel name is provided, the client refuses to send a shutdown request, ensuring that unscoped clients cannot affect other services.

### Adaptive Health Monitoring
The `HealthMonitor` component implements a robust loop for verifying server connectivity. It uses exponential backoff for transient errors, increasing the interval up to a maximum limit, while treating permanent failures (such as certificate errors or 404s) as fatal events. The monitor tracks consecutive and sliding-window failures to distinguish between temporary glitches and persistent issues. An `OnFatal` callback allows callers to define custom shutdown logic, defaulting to process termination to prevent silent degradation.

## Key Interfaces
- `NewClient(weftURLStr, tunnelName string)` initializes a new administrative client instance.
- `ListTunnels()` returns a map of active tunnel names to their current metrics.
- `Shutdown()` sends a termination signal to the specific tunnel associated with the client.
- `NewHealthMonitor(config HealthMonitorConfig)` creates a monitor with configurable retry and timing parameters.
- `Start()` begins the periodic health check loop, blocking until stopped or a fatal error occurs.
- `Stop()` safely halts the health monitoring goroutine.

## Dependencies
- `//src/auth`: Provides JWT generation and login utilities.
- `//types`: Shares common data structures used across the project.
- `@com_github_rs_zerolog//log`: Supplies structured logging capabilities.
- `@com_github_golang_jwt_jwt_v4//:jwt`: Handles JWT parsing and validation in tests.
- `@com_github_stretchr_testify//assert`: Offers assertion helpers for unit testing.

## Subcomponents
- `client.go`: Core client implementation for tunnel management.
- `health_monitor.go`: Adaptive health checking logic.
- `client_test.go`: Integration tests against a mock TLS server.
- `BUILD.bazel`: Bazel build rules for compilation and testing.