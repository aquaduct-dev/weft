<!-- docdaemon ts:2026-10-09T01:41:05Z hash:662ce4765052dc29 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for the `wireguard` Go library.

It configures the `go_library` target named `wireguard`, exposing it publicly for use by other packages in the repository. The source code is compiled from `wireguard.go`.

The library depends on several external Wireguard components:
- `conn`: Connection handling.
- `device`: Core device logic.
- `tun`: TUN interface abstraction.
- `tun/netstack`: Network stack integration for TUN.
- `wgtypes`: WireGuard types and configuration structures.

These dependencies are pulled from the `com_zx2c4_golang_wireguard` and `com_zx2c4_golang_wireguard_wgctrl` repositories, indicating this module wraps or extends the standard zx2c4 Wireguard implementation.