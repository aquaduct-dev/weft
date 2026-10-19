<!-- docdaemon ts:2026-10-19T23:25:46Z hash:80d3ee2a6a1093e3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains table-driven tests that pin the exact UAPI text output produced by `ConfigToString` for various WireGuard configuration scenarios.

The test suite ensures that the string serialization of `wgtypes.Config` matches the expected Userspace API format precisely. It uses deterministic helper functions (`testKey`, `hexOf`) to generate fixed key material, avoiding reliance on random secrets while keeping hex strings readable and stable.

### Test Cases
The `TestConfigToString` function covers four distinct states:
*   **Empty Config**: Verifies that an empty configuration results in a single newline character.
*   **Private Key & Port**: Checks serialization of `PrivateKey`, `ListenPort`, and the `ReplacePeers` flag.
*   **Peer Removal**: Ensures that peers marked with `Remove: true` emit only `public_key` and `remove=true`, ignoring other fields like `AllowedIPs` or `Endpoint`.
*   **Full Peer Configuration**: Validates the complete set of peer attributes, including multiple `AllowedIPs`, `Endpoint`, and `PersistentKeepaliveInterval`.

### Integration
These tests act as a contract for the `ConfigToString` function, preventing regressions in how configurations are formatted before being sent to userspace WireGuard devices. The use of fixed test data guarantees that any change in output formatting is immediately caught by the assertion logic.