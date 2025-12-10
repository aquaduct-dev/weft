# Weft 

[![Test](https://github.com/aquaduct-dev/weft/actions/workflows/test.yml/badge.svg)](https://github.com/aquaduct-dev/weft/actions/workflows/test.yml) [![Release](https://github.com/aquaduct-dev/weft/actions/workflows/release.yml/badge.svg)](https://github.com/aquaduct-dev/weft/actions/workflows/release.yml)

## What is this?

Weft is a Layer 4/Layer 7 tunnelling proxy built around [wireguard-go](https://github.com/WireGuard/wireguard-go) and designed for scalable, secure hosting of internet-facing resources from environments which lack public internet access.

## How does it work?

### Server

Start a Weft server on a host with at least one publically routable IP:

`weft server`

Optional arguments:
 - `--bind-ip`: Comma separated list of IPs that the server will listen on (defaults to auto-discovery).
 - `--port`: Server connection port (default 9092).
 - `--email`: Email address for LetsEncrypt ACME registration.
 - `--connection-secret`: Manually set the connection secret.
 - `--secret-file`: Path to write the generated connection secret to.
 - `--certs-cache-path`: Path to cache ACME certificates.
 - `--bind-interface`: Interface to bind the IP to (e.g., `eth0`).  If not set, the IP is not bound (the existing system IPs are used).
 - `--usage-reporting-url`: URL to post usage reports to.
 - `--cloudflare-token`: Cloudflare API Token for DNS updates.

The server will print a connection secret on startup.

### Tunnel

Start a Weft tunnel to expose a local service:

`weft tunnel weft://{connection-secret}@{your-server-ip} [local url] [remote url]`

Supported protocols:
 - `tcp>tcp` (plain proxy)
 - `tcp>http` (proxy HTTP requests from domain to TCP server)
 - `tcp>https` (terminate and proxy HTTPS requests from domain to TCP server)
 - `http>http` (proxy HTTP requests from domain to HTTP server)
 - `http>https` (terminate and proxy HTTPS requests from domain to HTTP server)
 - `https>https` (proxy HTTPS requests from domain to HTTPS server, stripping encryption and re-encrypting)
 - `udp>udp` (proxy UDP)

Optional arguments:
 - `--tunnel-name`: Logical name for the tunnel (defaults to hash of src|dst).
 - `--verbose`: Log detailed connection information.

Example:
`weft tunnel weft://secret@1.2.3.4 http://localhost:8080 https://my-app.example.com`

### Other Commands

**List Tunnels:**
`weft list [server url]`
Lists active tunnels on the server.
 - `--connection-secret`: Connection secret (if not in URL).
 - `--human-readable`, `-l`: Print bytes in human-readable format.

**Probe ACME:**
`weft probe [domain]`
Checks if the server can answer an ACME challenge for the given domain.
 - `--bind-ip`: IP to bind the probe listener to.

**One-off Proxy:**
`weft proxy [src url] [dst url]`
Starts a standalone proxy between two URLs.
 - `--proxy-name`: Logical name for the proxy.

## Under the Hood

### Tunnels

Weft uses `wireguard-go` to implement tunnels.  The server reserves a `10.1.0.0/16` block of addresses for the internal WireGuard network, and keeps track of which proxies have been assigned which addresses.  Each assigned address may only be used by the client to which it has been assigned; this is enforced in the peer config of the server Wireguard proxy.  The client side config allows the server to access from any IP.

When clients are removed, the address is freed and returned to the pool.  Subsequent clients may re-use the same address.

### Proxy

Both the server and the tunnel must run proxies.  The `/connect` method must establish a remote port listener on the server - a TCP/UDP proxy if necessary, or a VHostProxy if the connection uses HTTP/HTTPS. 

TCP and UDP proxies are simple on the server side: they simply proxy to the tunnel-side TCP/UDP proxy, which then forwards the request to whatever local target is being tunneled.

HTTP and HTTPS proxies are more complicated.  Each server-side `VHostProxy` must target the tunnel proxy port.  On the tunnel side, the proxy port should only forward TCP to the local HTTP server.

### HTTPS Zero-Trust Secret Verification

The Weft server does not have a signed TLS certificate.  Weft uses a short AES-based challenge to verify both the server and client possess the secret to prevent clients from connecting to fake servers.

1. Client `GET`s `/login`.
2. Server generates a random nonce and returns the string "server-<nonce>" encrypted with the common secret.
3. Client decrypts and verifies that the "server-" prefix is present.
4. Client encrypts the nonce and `POST`s it to `/login`.
5. Server decrypts the received ciphertext and verifies it matches the stored challenge.
6. On success, Server issues a short-lived JWT (~30m).
7. Client includes the JWT in the `Authorization` header for subsequent requests.

Subsequently, the token is used for healthchecks.  When it expires, the client must repeat the challenge to obtain a new token.

Notes:
- All AES operations use the shared connection secret as the key.  The nonce is single-use.
- The protocol allows both sides to prove they have the same secret without ever exchanging it.
- The JWT is used for all subsequent requests.

## Development

### Pre-commit Hook

To ensure code quality and build consistency, you can set up a git pre-commit hook that automatically runs `gazelle fix` and `bazel test //...` before each commit.

To install the hook, run:

```bash
./scripts/setup-pre-commit-hook.sh
```
