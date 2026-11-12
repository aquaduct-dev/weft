<!-- docdaemon ts:2026-11-12T09:41:11Z hash:70f0b6bd2916b23e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory contains the root configuration, build definitions, and entry points for the Weft tunnelling proxy application.

## Overview
The repository root orchestrates the development lifecycle of Weft, a Layer 4/Layer 7 tunnelling proxy using WireGuard. It defines the Bazel module structure, cross-compilation rules for multiple platforms, and container image packaging. The directory serves as the central hub for CI/CD pipelines, CLI entry points, and core infrastructure code, ensuring reproducible builds and automated releases across Linux, Windows, and macOS.

## Deep Dive
### Build System Configuration
`MODULE.bazel` and `BUILD.bazel` define the project's dependency graph and compilation targets. The system uses `rules_go` and `gazelle` to manage Go dependencies and synchronize BUILD files automatically. Cross-compilation is handled via `go_cross_binary`, producing platform-specific executables (`weft`, `weft_arm64`, etc.) that are later packaged into OCI images.

### Containerization
The `container/` directory defines rules for building multi-architecture Docker images. It combines AMD64 and ARM64 binaries into a single manifest list, allowing consumers to pull the correct variant based on their host architecture. These images are published to GitHub Container Registry with the `latest` tag.

### Application Entry Points
`main.go` initializes the Cobra-based CLI defined in `cmd/`. This package provides subcommands for managing proxies, tunnels, and the bastion server. The `src/` directory implements the core server logic, including authentication, tunnel lifecycle management, and network proxying.

### Automation and Testing
Scripts in `scripts/` enforce pre-commit checks and stabilize build metadata. The `test/` directory contains integration tests validating TCP/UDP proxying, HTTPS tunneling, and security features like MITM resistance. CI workflows in `.github/` automate testing and release processes.

## Key Interfaces
- `main()`: Application entry point delegating to `cmd.Execute()`.
- `rootCmd`: Base Cobra command defining global flags and execution flow.
- `Server`: Main struct holding HTTP listener, store, dataplane, and secrets.
- `UserspaceDevice`: Aggregates device logic, netstack, and TUN interface for WireGuard.
- `ConnectRequest`: Payload for initiating a new tunnel connection.
- `weft_image`: Multi-arch OCI image index published to GHCR.

## Dependencies
- Bazel and Bazelisk for build management.
- Go 1.25+ with `rules_go` and `gazelle`.
- `rules_oci` for container image building.
- `wireguard-go` for userspace tunnel management.
- Cobra for CLI framework.
- Zerolog for structured logging.

## Subcomponents
- `.github/workflows/`: CI/CD pipeline definitions.
- `cmd/`: Command-line interface implementation.
- `container/`: OCI image build rules.
- `scripts/`: Automation and hook installation scripts.
- `src/`: Core server and client infrastructure.
- `test/`: Integration test suite.
- `types/`: API payload structs.
- `wireguard/`: WireGuard device wrapper.