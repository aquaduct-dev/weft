<!-- docdaemon ts:2026-10-24T18:20:52Z hash:3d4f592499f40bf3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory serves as the root of the Weft project, defining the build system, CI/CD pipelines, and entry points for a Layer 4/Layer 7 tunnelling proxy.

## Overview
Weft exposes local resources via public IPs using WireGuard, featuring a server component for connection management and ACME certificates, alongside a client for traffic forwarding. The repository is structured to support reproducible multi-platform builds via Bazel, automated releases through GitHub Actions, and comprehensive integration testing. This layout separates CLI logic, core networking services, and infrastructure tooling to ensure modularity and maintainability.

## Deep Dive
### Build and Release Automation
The `.github/workflows` directory orchestrates continuous integration and release lifecycles. `test.yml` validates code integrity using Bazel with optimized caching, while `release.yml` handles multi-architecture packaging for Linux, Windows, and macOS. It generates binaries, verifies their correctness, publishes Docker images to GHCR, and creates Git tags. The `scripts/` directory supports this by installing pre-commit hooks that enforce Gazelle synchronization and test suite passes, ensuring build consistency.

### Core Application Logic
The `src/` package aggregates business logic, coordinating between the control plane (server) and data plane (proxies). The `server` package manages WireGuard lifecycle, peer state, and HTTP APIs, integrating with `proxy` for traffic forwarding and `acme` for TLS issuance. Security is handled by `auth` (zero-trust challenge-response) and `crypto` utilities. The `wireguard/` package provides a Go wrapper around `wireguard-go`, abstracting device creation and network binding for custom interface handling.

### Client Interface and Types
The `cmd/` package implements the Cobra-based CLI, providing commands for server management, tunnel establishment, and proxying. `main.go` delegates execution here, keeping bootstrap logic minimal. The `types/` package defines the API contract, structuring payloads for tunnel connections, health checks, and usage metrics to ensure consistent JSON serialization across the application.

## Key Interfaces
- `Execute()`: Main entry point for CLI execution in `cmd`.
- `Server`: Central coordinator for HTTP routes, state, and background workers in `src/server`.
- `Client`: Library struct for programmatic tunnel management and health monitoring in `src/client`.
- `UserspaceDevice`: Handle for managing WireGuard tunnel lifecycle and configuration in `wireguard`.
- `ConnectRequest` / `ConnectResponse`: API payloads for initiating and confirming tunnel connections in `types`.

## Dependencies
- Bazel and Bazelisk for build management
- Go 1.25+ with rules_go and gazelle
- wireguard-go for userspace tunnel implementation
- Cobra for CLI framework
- zerolog for structured logging
- Cloudflare DNS API for record updates

## Subcomponents
- `.github/workflows/test.yml`
- `.github/workflows/release.yml`
- `BUILD.bazel`
- `MODULE.bazel`
- `README.md`
- `cmd/`
- `container/`
- `main.go`
- `scripts/`
- `src/`
- `test/`
- `types/`
- `wireguard/`