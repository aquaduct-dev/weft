<!-- docdaemon ts:2026-10-19T23:26:00Z hash:06d89936d6b4e13a model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains table-driven unit tests for the `resolveServerIP` function, verifying address parsing and DNS resolution logic.

### Purpose
The test suite ensures that `resolveServerIP` correctly normalizes various input formats into a canonical IP string suitable for use as a WireGuard peer endpoint. It validates both successful resolutions and error handling paths.

### Test Cases
The `TestResolveServerIP` function uses a table-driven approach to cover:
- **Literal IPs**: IPv4 (`192.0.2.10`) and IPv6 (`2001:db8::1`) addresses, with and without ports.
- **Hostname Resolution**: Hostnames like `localhost` are resolved to loopback addresses (`127.0.0.1` or `::1`).
- **Error Handling**: Unresolvable hostnames (e.g., `.invalid` domains) and empty inputs must return specific error messages containing "failed to resolve server address".

### Design Notes
The test was updated to remove stale assumptions about hardcoded loopback endpoints, ensuring it now verifies the actual behavior of `resolveServerIP` against real resolution outcomes.