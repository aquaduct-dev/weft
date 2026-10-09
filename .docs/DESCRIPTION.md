<!-- docdaemon ts:2026-10-09T01:48:57Z hash:e7d744c257344349 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory serves as the root of the Weft project, defining the build system, CI/CD pipelines, and entry points for a WireGuard-based Layer 4/Layer 7 proxy.

## Overview
The repository root orchestrates the development lifecycle using Bazel for reproducible builds across Linux, Windows, and macOS. It integrates GitHub Actions to automate testing, multi-architecture containerization, and release publishing. The structure separates CLI logic (`cmd`), core business rules (`src`), and infrastructure wrappers (`wireguard`) to maintain modularity.

## Deep Dive
### Build Configuration
`BUILD.bazel` and `MODULE.bazel` define the Go toolchain, external dependencies, and cross-compilation targets. Gazelle manages dependency synchronization, while `rules_oci` handles multi-arch image indexing. Scripts in `scripts/` enforce pre-commit checks and stabilize build metadata via Git hashes.

### Application Entry Points
`main.go` delegates execution to the `cmd` package, which implements the Cobra CLI framework. This includes subcommands for server management, tunnel creation, and health probing. The `container/` directory defines Bazel rules to package these binaries into Alpine-based OCI images for GHCR distribution.

### Core Implementation
The `src/` directory contains the proxy logic, including HTTP routing, WireGuard device management, and ACME certificate handling. Security is enforced through zero-trust authentication and AES-GCM encryption. The `test/` directory provides Bash-based integration tests that validate traffic forwarding, billing metrics, and security constraints against mock servers.

## Key Interfaces
- `Execute()`: Main entry point for the CLI command tree.
- `UserspaceDevice`: Wrapper for managing WireGuard TUN interfaces and network binding.
- `Server`: Central coordinator for HTTP routes, peer state, and background workers.
- `Client`: Library struct for programmatic tunnel interaction and health monitoring.
- `ProxyManager`: Controller for creating and managing TCP/UDP/HTTP proxy tunnels.

## Dependencies
- Bazel and Bazelisk for build management
- Go 1.25.4 (via `go.mod`)
- GitHub Actions Cache and OIDC tokens
- `rules_go`, `gazelle`, `rules_oci` for Bazel extensions
- `cobra`, `zerolog`, `quic-go`, `netlink` for Go runtime

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