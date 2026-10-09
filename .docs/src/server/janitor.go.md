<!-- docdaemon ts:2026-10-09T01:40:43Z hash:05897a625ebd1bba model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The Janitor periodically identifies and removes stale tunnels that have not reported health checks within a configured threshold.

## Purpose
This file implements the `Janitor` type, which runs in the background to maintain system hygiene by cleaning up inactive resources. It ensures that tunnels which fail to report their status are eventually removed, preventing resource leaks while providing an opportunity to log usage metrics before deletion.

## Key Components

### Type: `Janitor`
A struct holding the configuration and dependencies for the cleanup process.
- **interval**: The frequency of the cleanup loop.
- **store**: Interface to query tunnel last-seen timestamps (`TunnelStore`).
- **cleanup**: Callback invoked to remove a specific tunnel by name.
- **report**: Callback invoked to log or record usage data for a batch of tunnels.
- **closing**: Function indicating if the server is shutting down, allowing graceful exit.

### Functions

#### `NewJanitor`
Constructs a new `Janitor` instance with the provided interval, store, callbacks, and shutdown signal.

#### `Start` / `Stop`
Manages the lifecycle of the janitor goroutine. `Start` launches the periodic sweep loop, while `Stop` signals termination and waits for the goroutine to finish using a `sync.WaitGroup`.

#### `run`
The main loop that ticks at the specified interval. It exits immediately if the `closing` function returns true or if the `stopCh` is closed.

#### `sweep`
Executed on each tick. It identifies tunnels whose last seen timestamp is older than three times the interval (`3 * j.interval`). It first reports these tunnels via the `report` callback, then iterates through them again to verify they are still stale before invoking the `cleanup` callback.