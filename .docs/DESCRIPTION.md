<!-- docdaemon ts:2026-11-01T18:06:29Z hash:704f2369c4f11e1d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory serves as the root of the Weft project, defining the build system, CI/CD pipelines, and entry points for a Layer 4/Layer 7 tunnelling proxy.

## Overview
Weft exposes local resources via public IPs using WireGuard tunnels and ACME-managed TLS certificates. The repository is structured around Bazel for reproducible, multi-platform builds and GitHub Actions for automated testing and release. It separates CLI logic, core server infrastructure, and container packaging into distinct packages to maintain modularity.

## Deep Dive
### Build System
`MODULE.bazel` and `BUILD.bazel` configure the Go toolchain, Gazelle dependency management, and OCI image rules. Cross-compilation targets produce binaries for Linux (AMD64/ARM64), Windows, and macOS. The `container` package orchestrates multi-architecture image indexing, ensuring consumers pull the correct variant for their host CPU.

### Core Infrastructure
The `src` package implements the bastion server, handling JWT-based authentication, tunnel lifecycle management, and reverse proxying. It enforces zero-trust security through challenge-response protocols and manages dynamic IP allocation. Background workers clean up stale tunnels and report usage metrics to external endpoints.

### Command Line Interface
The `cmd` package provides the user-facing toolset using Cobra. Subcommands manage server instances, establish persistent WireGuard tunnels, and create ephemeral proxies. It handles graceful shutdowns, signal trapping, and verbose logging configuration.

### Testing and Automation
Integration tests in `test/` validate TCP/UDP forwarding, HTTPS tunneling, and billing accuracy against compiled binaries. Scripts in `scripts/` enforce pre-commit checks via Gazelle and stabilize build metadata using Git hashes to optimize Bazel caching.

## Key Interfaces
- `rootCmd`: Base Cobra command for global flags and execution.
- `Server`: Main struct holding HTTP listener, store, and dataplane.
- `UserspaceDevice`: Wrapper for managing WireGuard TUN devices.
- `ConnectRequest` / `ConnectResponse`: API payloads for tunnel establishment.
- `weft_image`: Multi-arch OCI index published to GHCR.

## Dependencies
- Bazel and Bazelisk for build orchestration.
- Go 1.25+ with `rules_go` and `gazelle`.
- `wireguard-go` for userspace network stack integration.
- `cobra` for CLI structure and `zerolog` for logging.
- `prometheus` client libraries for metrics export.

## Subcomponents
- `.github/workflows/`: CI/CD pipeline definitions.
- `cmd/`: CLI implementation and subcommands.
- `container/`: OCI image build rules.
- `scripts/`: Pre-commit hooks and status scripts.
- `src/`: Server logic, middleware, and handlers.
- `test/`: Integration test suite.
- `types/`: API payload structs.
- `wireguard/`: WireGuard device abstraction.