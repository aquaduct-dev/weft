# Weft 

[![Test](https://github.com/aquaduct-dev/weft/actions/workflows/test.yml/badge.svg)](https://github.com/aquaduct-dev/weft/actions/workflows/test.yml) [![Release](https://github.com/aquaduct-dev/weft/actions/workflows/release.yml/badge.svg)](https://github.com/aquaduct-dev/weft/actions/workflows/release.yml)

## Installation

### Homebrew (macOS and Linux)

```bash
brew tap aquaduct-dev/weft
brew install weft
```

### Debian / Ubuntu (deb)

```bash
# Download the latest .deb package
curl -LO https://github.com/aquaduct-dev/weft/releases/latest/download/weft_amd64.deb

# Install
sudo dpkg -i weft_amd64.deb
```

For ARM64 systems:
```bash
curl -LO https://github.com/aquaduct-dev/weft/releases/latest/download/weft_arm64.deb
sudo dpkg -i weft_arm64.deb
```

### RHEL / Fedora / CentOS (rpm)

```bash
# Download the latest .rpm package
curl -LO https://github.com/aquaduct-dev/weft/releases/latest/download/weft_amd64.rpm

# Install
sudo rpm -i weft_amd64.rpm
```

For ARM64 systems:
```bash
curl -LO https://github.com/aquaduct-dev/weft/releases/latest/download/weft_arm64.rpm
sudo rpm -i weft_arm64.rpm
```

### Manual Download

Download the appropriate binary for your platform from the [Releases page](https://github.com/aquaduct-dev/weft/releases):

| Platform | Architecture | Download |
|----------|--------------|----------|
| Linux | x86_64 | `weft-linux-amd64` |
| Linux | ARM64 | `weft-linux-arm64` |
| macOS | Intel | `weft-darwin-amd64` |
| macOS | Apple Silicon | `weft-darwin-arm64` |
| Windows | x86_64 | `weft-windows-amd64.exe` |

```bash
# Example: Download and install on Linux x86_64
curl -LO https://github.com/aquaduct-dev/weft/releases/latest/download/weft-linux-amd64
chmod +x weft-linux-amd64
sudo mv weft-linux-amd64 /usr/local/bin/weft
```

### Docker

```bash
docker pull ghcr.io/aquaduct-dev/weft:latest
```

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

#### Fancy URL Support (HTTP/HTTPS)

The tunnel supports URL syntax for HTTP routes which add significant functionality.

##### Path Rewriting

The tunnel can rewrite HTTP paths.  For example, take this command:

`weft tunnel weft://secret@1.2.3.4/test http://localhost:8080 https://my-app.example.com/api/v1`

A request to 'https://my-app.example.com/api/v1/create` will be tunneled to `http://localhost:8080/test/create`.

##### Match Query Parameters

The tunnel can check query parameters and route based on them.  For example:

`weft tunnel weft://secret@1.2.3.4 http://localhost:8080 https://my-app.example.com?token=[token-regex]`

A request to 'https://my-app.example.com/api/v1/create` will be tunneled to `http://localhost:8080/api/v1/create` - but only if the query string contains a key named `token` with a value that matches `[token-regex]`.  Regexes are parsed using RE2 syntax.

##### Match Headers

The tunnel can check request headers and route based on them.  For example:

`weft tunnel weft://secret@1.2.3.4 http://localhost:8080 https://my-app.example.com#Authorization=[authorization-regex]&Set-Cookie=.*`

A request to 'https://my-app.example.com/api/v1/create` will be tunneled to `http://localhost:8080/api/v1/create` - but only if the request has an `Authorization` header matching `[authorization-regex]` AND a `Set-Cookie` header matching `.*` (i.e. any value).

##### Match Method

The tunnel can check request methods and route based on them.  For example:

`weft tunnel weft://secret@1.2.3.4 http://localhost:8080 https://my-app.example.com#POST&Authorization=[authorization-regex]`

A request to 'https://my-app.example.com/api/v1/create` will be tunneled to `http://localhost:8080/api/v1/create` - but only if the request has an `Authorization` header matching `[authorization-regex]` AND is a `POST` request.

##### Modify headers

The tunnel can modify incoming request headers.  For example:

`weft tunnel weft://secret@1.2.3.4 http://localhost:8080/#Forwarded=true&X-Forwarded-For=!del&Authorization=+auth https://my-app.example.com`

A request to 'https://my-app.example.com/api/v1/create` will be tunneled to `http://localhost:8080/api/v1/create`.  The request that is sent to `http://localhost:8080` will have header `Forwarded` set to `true`, `X-Forwarded-For` removed, and `Authorization` set to `auth` if it was not previously set.

##### Redirects

It is even possible to set up a tunnel which does not tunnel at all, but just configures an HTTP redirect.  For example:

`weft tunnel weft://secret@1.2.3.4 http://localhost:8080/#redirect https://my-app.example.com`

A request to 'https://my-app.example.com/api/v1/create` will get an `HTTP 302` redirect to `http://localhost:8080`.

##### Combining multiple matchers

The `weft` implementation will evaluate rules in order from most specific to least specific.  Route A is considered more specific than route B if route A has more matchers.

Matchers can be easily combined just by including the URL components.  For example:

`weft tunnel weft://secret@1.2.3.4 http://localhost:8080/api?query=true#X-Forwarded-For=!del&Authorization=+auth https://my-app.example.com/api/v1/`

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

The Weft server uses a self-signed TLS certificate. To prevent man-in-the-middle attacks, Weft uses an encrypted challenge-response protocol that also securely delivers the server's certificate to the client.

**Authentication Flow:**

1. Client `GET`s `/login` (using `InsecureSkipVerify` for this initial request only).
2. Server generates a random nonce and returns the string "server-<nonce>" encrypted with the connection secret.
3. Client decrypts and verifies that the "server-" prefix is present — proving the server has the secret.
4. Client encrypts the nonce and `POST`s it to `/login`.
5. Server decrypts the received ciphertext and verifies it matches the stored challenge.
6. On success, Server issues:
   - A short-lived JWT (~30m)
   - The server's TLS certificate PEM, **encrypted with the connection secret**
7. Client decrypts the certificate and uses it as the trusted root CA for all subsequent TLS connections.
8. Client includes the JWT in the `Authorization` header for subsequent requests.

**Why This Prevents MITM:**

- A man-in-the-middle attacker cannot decrypt the certificate because they don't have the connection secret.
- After the initial handshake, all connections are validated against the encrypted-and-delivered certificate.
- Even if an attacker intercepts the initial TLS handshake, they cannot produce a valid encrypted certificate that the client will trust.

**Notes:**
- All AES operations use the shared connection secret as the key. The nonce is single-use.
- The protocol allows both sides to prove they have the same secret without ever exchanging it.
- The JWT is used for all subsequent requests. When it expires, the client repeats the challenge to obtain a new token.

## Development

### Pre-commit Hook

To ensure code quality and build consistency, you can set up a git pre-commit hook that automatically runs `gazelle fix` and `bazel test //...` before each commit.

To install the hook, run:

```bash
./scripts/setup-pre-commit-hook.sh
```
