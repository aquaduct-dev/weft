<!-- docdaemon ts:2026-10-29T21:07:31Z hash:5da0601f31475d5b model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory implements the core Weft server infrastructure, including authentication, tunneling, and network proxying.

## Overview
The `src` package orchestrates the control plane for the Weft mesh network, managing client connections, WireGuard peer provisioning, and traffic routing. It provides a unified entry point for Bazel tests that validate connectivity, eviction logic, and tunnel functionality across the entire system. The codebase is structured into specialized sub-packages to separate concerns such as cryptographic handshakes, ACME certificate management, and protocol-agnostic proxying.

## Deep Dive
### Authentication and Security
The `auth` package handles zero-trust challenge-response login, JWT lifecycle management, and AES-GCM encryption for secure tunnel establishment. It ensures only authorized clients can connect by validating encrypted challenges and optional TLS pinning. The `crypto` package supports this with symmetric encryption utilities and self-signed certificate generation for internal communication.

### Tunnel and Proxy Management
The `server` package manages the HTTP control plane, coordinating tunnel lifecycles, IP allocation, and background janitor tasks for stale peer cleanup. The `proxy` package implements protocol-agnostic forwarding for TCP, UDP, and HTTP/HTTPS traffic, integrating with WireGuard via gVisor NetStack. It includes virtual host support with automatic TLS certificates managed by the `acme` package, which proxies HTTP-01 challenges to sibling nodes in clustered environments to bypass Let's Encrypt redirect restrictions.

### Client and Infrastructure Utilities
The `client` package provides programmatic access to administrative endpoints and an adaptive health monitor that adjusts retry intervals based on server responses. The `tunnel` package handles client-side WireGuard device creation and local proxy configuration. Shared utilities in `internal` define immutable network defaults and URL parsing helpers, while `dns` synchronizes Cloudflare records with strict zone resolution logic. Logging is centralized in `logging`, adapting output formats based on environment variables.

## Key Interfaces
*   `GetToken`: Executes challenge-response login and returns a JWT and encrypted certificate.
*   `NewClient`: Initializes an administrative client for tunnel management and health monitoring.
*   `ProxyManager`: Coordinates active proxy instances and enforces naming uniqueness.
*   `Server`: Main struct holding HTTP listener, store, dataplane, and secrets.
*   `Tunnel`: Orchestrates full connection lifecycle including device creation and proxy startup.
*   `Init`: Configures the global zerolog instance with environment-appropriate formatting.
*   `UpdateRecord`: Synchronizes DNS records for a hostname using the provided API token.

## Dependencies
*   `github.com/cloudflare/cloudflare-go`: Official Cloudflare Go SDK.
*   `github.com/golang-jwt/jwt/v4`: JWT parsing and validation.
*   `github.com/onsi/ginkgo/v2` and `github.com/onsi/gomega`: Testing framework.
*   `github.com/quic-go/quic-go`: HTTP/3 QUIC support.
*   `github.com/rs/zerolog`: Structured logging.
*   `golang.org/x/crypto/acme/autocert`: Automatic certificate management.
*   `google.golang.org/grpc`: gRPC client library.
*   `prometheus/client_golang`: Prometheus metrics instrumentation.
*   `wgctrl`: WireGuard configuration management.

## Subcomponents
*   `acme/`: Certificate acquisition and HTTP-01 challenge proxying.
*   `auth/`: Zero-trust authentication and JWT transport management.
*   `client/`: Administrative client library and health monitoring.
*   `crypto/`: Symmetric encryption and certificate generation.
*   `dns/`: Cloudflare DNS record synchronization.
*   `internal/`: Network constants and utility functions.
*   `logging/`: Centralized application logging configuration.
*   `proxy/`: Protocol-agnostic traffic forwarding and virtual hosts.
*   `server/`: Control plane HTTP server and tunnel lifecycle management.
*   `tunnel/`: Client-side WireGuard setup and proxy integration.
*   `version/`: Build metadata injection and reporting.
*   `BUILD.bazel`: Aggregated test target definition.
*   `server_connectivity_test.go`: Backend unreachable eviction tests.
*   `server_eviction_repro_test.go`: Crash-loop kill chain reproduction.
*   `server_tunnel_suite_test.go`: Ginkgo suite bootstrap.
*   `server_tunnel_test.go`: End-to-end tunnel connectivity tests.