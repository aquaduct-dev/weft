<!-- docdaemon ts:2026-10-09T01:40:49Z hash:3dae8d81294b6277 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This test reproduces the tunnel crash-loop kill chain by verifying that server-side peer eviction leads to a fatal client health check failure.

### Purpose
The file validates the specific sequence where a WireGuard data-path break triggers `F-9 WGAwareRoundTripper` cleanup, which evicts the peer. This eviction causes `/healthcheck` to return 404, which the client's `HealthMonitor` classifies as permanent, causing the process to exit (CrashLoopBackOff). It isolates this weft-controlled logic from environmental packet loss.

### Key Components
*   **Setup**: Starts a local `server.Server` and authenticates a client using real tokens.
*   **Eviction Injection**: Calls `tunnelSrv.RemoveTunnel(tunnelName)` directly to simulate the cleanup behavior of production.
*   **Verification**:
    *   Confirms the server returns `http.StatusNotFound` for the evicted peer.
    *   Instantiates `client.HealthMonitor` with a custom `OnFatal` callback.
    *   Asserts that the monitor fires `OnFatal` upon receiving the 404, confirming the crash-loop trigger.