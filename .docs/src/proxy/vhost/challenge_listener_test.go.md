<!-- docdaemon ts:2026-10-30T02:43:10Z hash:d3ecfb1d350e979f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains tests verifying that the ACME challenge listener remains persistent and reachable for sibling bastions, even when no specific hosts are configured.

### Purpose
The `StartChallengeListener` ensures port `:80` stays open to allow reachability probes from other nodes in a round-robin DNS setup. Previously, the listener closed when its last route disappeared, causing probe failures and cascading shutdowns across bastions. These tests validate that behavior is corrected.

### Key Tests

*   **`TestStartChallengeListener_SiblingAnswersProbeWithNoHosts`**: Verifies that a node with no ACME hosts still responds to probes (returning 403 or 404), ensuring siblings can verify reachability.
*   **`TestStartChallengeListener_SurvivesLastACMEHostClosing`**: Confirms the listener does not close after an ACME issuance completes and its associated host route is removed. This prevents the "connection refused" errors seen in previous deployments.
*   **`TestChallengeListener_ClosesWithoutKeepOpen`**: Validates that without the persistent listener logic (`keepOpen`), the standard lifecycle correctly closes the port when the last route is removed, ensuring backward compatibility for non-challenge scenarios.

### Helper Functions
*   **`freePort`**: Allocates a random available TCP port for isolated test execution.
*   **`probeStatus`**: Sends an HTTP HEAD request to simulate the ACME challenge probe, checking if the listener is active and responding.
*   **`waitListening`**: Polls the port until it accepts connections or times out, handling race conditions during startup.