<!-- docdaemon ts:2026-11-12T09:10:28Z hash:73600c692fa7d2d0 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `LookupIPFresh` function, verifying its logic for resolving hostnames via authoritative nameservers while avoiding cached negative responses.

The test suite ensures that `LookupIPFresh` prioritizes zone-specific nameserver lookups over the system resolver. This design prevents stale NXDOMAIN cache entries from blocking certificate issuance for newly registered hosts, a critical fix for ACME reachability probes.

Key verification points include:
- **Authoritative Resolution**: Confirms that new hosts are resolved using the zone's own nameservers (`lookupNS`) rather than the global system resolver.
- **Fallback Logic**: Verifies that if all authoritative servers are unreachable, the function falls back to the system resolver (`systemLookupIP`).
- **NXDOMAIN Handling**: Ensures that an explicit "no such host" response from an authoritative server is treated as a final failure, preventing unnecessary fallbacks.
- **Literal IPs**: Checks that IP literals bypass DNS resolution entirely and are returned directly.
- **Error Propagation**: Validates correct error handling when specific nameservers time out or fail, ensuring the resolver attempts subsequent servers in the zone.