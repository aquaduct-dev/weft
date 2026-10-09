<!-- docdaemon ts:2026-10-09T01:40:31Z hash:8e35df015e879adc model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the ACME challenge validation and host registration logic within the virtual host proxy.

It verifies that `CanPassACMEChallenge` correctly rejects loopback, private, and empty hosts to prevent SSRF, while allowing public IPs that pass HTTP probes. The tests use dependency injection via `withSeams` to mock DNS lookups (`lookupIP`) and HTTP probing (`probeACMEChallengeFn`).

Key scenarios covered include:
- **Security Guards**: Ensuring loopback addresses (e.g., `localhost`, `127.0.0.1`) are always denied.
- **DNS Resolution**: Handling cases with no public records, lookup errors, or single/multiple A records.
- **RR Thresholds**: Validating that a majority of resolved IP records must successfully respond to the ACME challenge probe.
- **Registration Order**: Confirming that `AddHostWithACME` binds the ACME listener on port 80 *before* executing the challenge probe, preventing race conditions where the probe fails due to an unbound listener.