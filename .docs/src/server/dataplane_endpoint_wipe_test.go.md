<!-- docdaemon ts:2026-10-09T01:40:35Z hash:9b9b914262e1f08f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains a regression test ensuring that removing one WireGuard tunnel does not inadvertently wipe the learned network endpoints of other active tunnels.

## Purpose
The `TestRemovingOneTunnelPreservesBystanderEndpoints` function verifies that `UpdateWireGuardConfig` performs an incremental peer reconciliation rather than a full device rebuild with `replace_peers=true`. A full rebuild would trigger `RemoveAllPeers()`, erasing roaming-learned endpoints for all peers, which causes disruption to surviving tunnels. This test guards against such regressions by asserting that bystander peers retain their state when a different peer is removed.

## Key Components

### `endpointFor(ipc, pubHex string) string`
Parses an IpcGet dump string to extract the endpoint associated with a specific public key (provided in hex format). Returns an empty string if the peer or its endpoint is not found.

### `TestRemovingOneTunnelPreservesBystanderEndpoints(t *testing.T)`
1.  **Setup**: Initializes a `TunnelDataplane` and registers two peers (`tunnel-a` and `tunnel-b`) with distinct IPs.
2.  **State Injection**: Simulates production conditions by injecting learned endpoints for both peers via `IpcSet`, mimicking the behavior of client keepalives.
3.  **Precondition Check**: Verifies that both endpoints are correctly recorded in the device configuration.
4.  **Action**: Removes `tunnel-b` from the peer map and calls `UpdateWireGuardConfig`, simulating the removal path triggered by `RemoveTunnel`.
5.  **Verification**:
    *   Asserts `tunnel-a`'s endpoint remains intact. Failure indicates a regression to a destructive `replace_peers` rebuild.
    *   Asserts `tunnel-b` is fully removed.