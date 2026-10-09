<!-- docdaemon ts:2026-10-09T01:40:32Z hash:399e9cf7ed55162f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains concurrency regression tests to verify that race conditions in `VHostProxyManager` and `VHostProxy` are resolved.

### Purpose
The tests ensure thread-safety for concurrent access to internal maps (`acmeHosts`, `tlsConfigs`) protected by mutexes. They specifically guard against regressions of data races previously reported under Go's `-race` detector.

### Key Functions

*   **`TestACMEHostsAndPolicy_NoRace`**: Concurrently writes to the `acmeHosts` map via `AddACMEHost` (simulated) and reads from the `HostPolicy`. It verifies that locking is correctly applied in both mutator and reader paths.
*   **`TestTLSGetCertificate_NoRace`**: Concurrently updates the `tlsConfigs` map and invokes the TLS `GetCertificate` callback. It ensures that snapshotting the config under `p.mu.RLock` prevents races during certificate lookup.
*   **`hostName`**: Helper to generate unique, deterministic hostnames for test iterations.
*   **`tlsGetCertificateForTest`**: A test helper that mirrors the locking logic of the production `GetCertificate` closure, allowing direct invocation without starting a real TLS listener.