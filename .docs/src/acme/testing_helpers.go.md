<!-- docdaemon ts:2026-10-09T01:40:09Z hash:0ee5300ef7c339b6 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides exported test seams to mock DNS lookups and local network interface addresses for deterministic testing in other packages.

## Purpose
The `acme` package uses internal variables (`lookupIP`, `interfaceAddrs`) to abstract system calls. This helper file exposes functions to swap these variables at runtime, allowing tests in external packages (like `proxy/vhost`) to inject deterministic state without modifying production logic. These functions are strictly for testing and must not be used in production code.

## Functions

### DNS Seams
- **`SwapLookupIPForTest(hostsToIPs map[string][]string) func(string) ([]net.IP, error)`**: Replaces the global `lookupIP` function with a closure that returns specified IPs for given hosts. Returns the previous function for restoration. Hosts not in the map return a "no such host" error.
- **`RestoreLookupIPForTest(prev func(string) ([]net.IP, error))`**: Restores the original `lookupIP` function returned by `SwapLookupIPForTest`.

### Interface Address Seams
- **`SwapInterfaceAddrsForTest(localAddrs []string) func() ([]net.Addr, error)`**: Replaces the global `interfaceAddrs` function with a closure returning the provided IP addresses as `*net.IPNet`. Returns the previous function for restoration.
- **`RestoreInterfaceAddrsForTest(prev func() ([]net.Addr, error))`**: Restores the original `interfaceAddrs` function returned by `SwapInterfaceAddrsForTest`.