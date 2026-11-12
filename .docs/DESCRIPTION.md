<!-- docdaemon ts:2026-11-12T09:11:49Z hash:bda99b79129941f4 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory serves as the root of the Weft project, defining the build system, CI/CD pipelines, and entry points for a Layer 4/Layer 7 tunnelling proxy.

## Overview
Weft exposes local resources via public IPs using WireGuard tunnels and ACME-managed TLS certificates. The repository is structured around Bazel for reproducible, multi-platform builds and GitHub Actions for automated testing and release. It separates CLI logic, core server infrastructure, and container packaging into distinct packages to maintain modularity.

## Deep Dive
### Build System
`BUILD.bazel` and `MODULE.bazel` configure Gazelle and rules_oci to compile Go binaries for Linux, Windows, and macOS. Cross-compilation targets (`weft`, `weft_arm64`, etc.) feed into OCI image layers, which are indexed into a multi-architecture manifest pushed to GHCR. Stability is ensured by `workspace_status.sh`, which injects stable Git metadata into Bazel’s `x_defs` to optimize caching.

### Core Infrastructure
The `src` package implements the zero-trust authentication flow, JWT management, and multi-protocol proxying. It handles ACME certificate issuance with fan-out challenge validation for round-robin DNS environments. The `wireguard` package wraps `wireguard-go` to manage userspace TUN devices and network binding, while `types` defines the API contract for tunnel connections and usage reporting.

### CLI and Testing
The `cmd` package provides the user interface via Cobra subcommands for managing servers, tunnels, and proxies. Integration tests in `test/` validate TCP/UDP forwarding, HTTPS routing, and billing accuracy using mock servers and compiled binaries. Scripts in `scripts/` enforce pre-commit checks to keep BUILD files synchronized with source code.

## Key Interfaces
- `rootCmd`: Base Cobra command for global flags and execution.
- `Server`: Control plane struct holding HTTP listeners and dataplane state.
- `Tunnel`: Client-side orchestrator for WireGuard device lifecycle.
- `UserspaceDevice`: Wrapper for initializing and controlling WireGuard instances.
- `ConnectRequest`: Payload for initiating new tunnel connections.
- `HealthMonitor`: Adaptive loop verifying server connectivity with backoff.

## Dependencies
- Bazel and Bazelisk for build management.
- Go 1.25+ with standard library networking and crypto packages.
- `github.com/spf13/cobra` for CLI structure.
- `github.com/rs/zerolog` for structured logging.
- `com_zx2c4_golang_wireguard` for userspace tunnel implementation.
- `github.com/cloudflare/cloudflare-go` for DNS synchronization.

## Subcomponents
- `.github/workflows/`: CI/CD pipeline definitions.
- `cmd/`: Command-line interface implementation.
- `container/`: OCI image build and publishing rules.
- `scripts/`: Automation scripts for hooks and build stability.
- `src/`: Core server, client, and proxy logic.
- `test/`: Integration test suite.
- `types/`: API payload struct definitions.
- `wireguard/`: WireGuard device abstraction layer.
- `main.go`: Application entry point.