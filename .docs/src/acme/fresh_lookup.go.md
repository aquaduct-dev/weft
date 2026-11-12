<!-- docdaemon ts:2026-11-12T09:10:28Z hash:a6ae3ad8448eac4a model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a DNS resolution mechanism that queries authoritative nameservers directly to avoid cached NXDOMAIN errors during new host registration.

The `LookupIPFresh` function resolves a hostname by first attempting to find the zone's authoritative nameservers. It walks up from the host's parent domain, querying for NS records to identify the closest enclosing zone. This approach bypasses the system resolver's cache, which is critical because new hosts are often registered moments before their first certificate request. If the system resolver had previously seen a non-existent record, it might cache an NXDOMAIN response for up to 30 minutes (based on the SOA minimum), causing subsequent lookups to fail even after the A record exists.

By querying authoritative servers directly, the function ensures it sees the current state of the zone. If the authoritative servers confirm the record does not exist yet, the error is returned immediately. If they do not respond or if no authoritative servers are found, the function falls back to the standard system resolver (`net.LookupIP`).

The implementation uses test seams (`systemLookupIP`, `lookupNS`, `queryAt`) to allow dependency injection in tests, enabling verification of logic without relying on external network conditions.