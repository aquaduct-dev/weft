<!-- docdaemon ts:2026-10-09T01:40:40Z hash:27f3d22005d409fe model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides HTTP handlers for exposing tunnel metrics in Prometheus format and retrieving detailed tunnel statistics as JSON.

### Purpose
The `server` package exposes operational data about active tunnels. It supports two distinct endpoints: one for machine-readable scraping by monitoring systems (Prometheus) and another for human or programmatic inspection of current state (JSON).

### Key Functions

#### `MetricsHandler`
Serves metrics in the Prometheus exposition format (`text/plain; version=0.0.4`).
*   **Authentication**: Requires Basic Auth. The username is compared against `s.ConnectionSecret` using constant-time comparison to prevent timing attacks.
*   **Data Collection**: Retrieves proxy counters from `s.Dataplane` and peer information from `s.Store`.
*   **Output**: Iterates over all peers, formatting byte transmission (`Tx`) and reception (`Rx`) totals into metric lines.
*   **Safety**: Uses `promQuote` to escape backslashes, quotes, and newlines in label values (tunnel ID, source, destination) to prevent injection or parsing errors in the scrape output.

#### `ListHandler`
Returns a JSON object mapping tunnel names to their usage statistics.
*   **Structure**: Each entry includes `tx`, `rx` (uint64), `src`, and `dst` fields.
*   **Data Source**: Aggregates data from `s.Dataplane.GetProxyCounters()` and `s.Store.GetAllPeers()`.
*   **Output**: Sets `Content-Type` to `application/json` and encodes the response map.

### Integration
These handlers are part of the `Server` struct, relying on `Dataplane` for live traffic counts and `Store` for persistent peer configuration. They do not modify state, serving purely observational roles within the application lifecycle.