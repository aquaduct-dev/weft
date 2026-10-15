<!-- docdaemon ts:2026-10-15T20:42:04Z hash:897c224799454c81 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script performs an end-to-end integration test for the `weft proxy` command, verifying that it correctly terminates TLS using a static CA-signed certificate and routes multiple hostnames to distinct backend services.

## Purpose
The test validates the specific mode used by `weft-operator`'s `WeftLocalDNSReflector`, where a single process serves HTTPS traffic for several public hostnames using pre-generated certificates rather than ACME. It ensures that the proxy correctly identifies requests based on the SNI (Server Name Indication) header and forwards them to the appropriate upstream HTTP backend.

## Key Components

### Certificate Generation
The script dynamically generates a test Certificate Authority (CA) and a leaf certificate containing Subject Alternative Names (SANs) for both `a.weft.test` and `b.weft.test`. This allows a single TLS connection to securely serve multiple domains without certificate errors during verification.

### Backend Simulation
Two lightweight Python HTTP servers are spawned as background processes. Each returns a unique string (`hello-from-a` or `hello-from-b`) when accessed, allowing the test to verify that routing logic correctly distinguishes between the two hostnames.

### Proxy Execution
The `weft proxy` binary is started with the `--tls-cert` and `--tls-key` flags pointing to the generated leaf certificate. Two mapping pairs are provided:
- `http://127.0.0.1:<A_PORT>` mapped to `https://a.weft.test:<PROXY_PORT>`
- `http://127.0.0.1:<B_PORT>` mapped to `https://b.weft.test:<PROXY_PORT>`

### Verification Loop
Using `curl` with `--cacert` and `--resolve`, the script sends requests to both hostnames. It retries up to 10 times to account for startup latency, checking that each hostname receives the response from its corresponding backend. If successful, the exit code is 0; otherwise, it exits with code 3 and dumps the proxy log for debugging.