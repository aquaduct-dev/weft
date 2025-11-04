# Weft Tunnel

## What is this?

Weft is a Layer 4/Layer 7 proxy built around [wireguard-go](https://github.com/WireGuard/wireguard-go) and designed for scalable, secure hosting of internet-facing resources from environments which lack public internet access.

## How does it work?

Start a Weft server on a host with at least one publically routable IP:

`weft server`

There are optional arguments:
 - `--email` can be passed an email address for use with LetsEncrypt.
 - `--bind-ips` can be passed a comma separated list of IPs that the server will listen on.
 - `--use-secret-per-ip` can be passed to create a separate connection secret for each IP address.
 - `--port` can be passed a port to change the server connection port (default 9092).
 - `--verbose` can be passed to have the server log detailed connection information.
 - `--opentelemetry-connection-string` can be passed to log OpenTelemetry metrics.

The server will print a connection secret (and optionally write it to a file) on startup.

Then, start a Weft tunnel:

`weft tunnel weft://{connection-secret}@{your-server-ip} [local url] [remote url]`

Supported protocols are:
 - `tcp://`
 - `udp://`
 - `http://`
 - `https://`

The optional arguments are:
 - `--tls-secret` can be passed to directly provision a secret.
 - `--verbose` can be passed to have the tunnel log detailed connection information.
 - `--opentelemetery-connection-string` can be passed to have the tunnel log OpenTelemetery metrics.

Otherwise, if the DNS records are set up correctly, the server will attempt an `HTTP01` challenge to acquire a certificate for the domain in question.

That's it!  Your local URL is now proxied and available on the internet at the remote url.

## Under the Hood

### Tunnels

Weft uses `wireguard-go` to implement tunnels.  The server reserves a `10.1.0.0/16` block of addresses for the internal WireGuard network, and keeps track of which proxies have been assigned which addresses.  Each assigned address may only be used by the client to which it has been assigned; this is enforced in the peer config of the server Wireguard proxy.  The client side config allows the server to access from any IP.

When clients are removed, the address is freed and returned to the pool.  Subsequent clients may re-use the same address.

### Proxy

Both the server and the tunnel must run proxies.  The `/connect` method must establish a remote port listener on the server - a TCP/UDP proxy if necessary, or a VHostProxy if the connection uses HTTP/HTTPS. 

TCP and UDP proxies are simple on the server side: they simply proxy to the tunnel-side TCP/UDP proxy, which then forwards the request to whatever local target is being tunneled.

HTTP and HTTPS proxies are more complicated.  Each server-side `VHostProxy` must target the tunnel proxy port.  On the tunnel side, the proxy port should only forward TCP to the local HTTP server.


The server should only ever proxy TCP/UDP from the client, but the client should proxy TCP/UDP/HTTP/HTTPS from its local network (allowing it to use local DNS) to TCP/UDP connections on the server.

### HTTPS Zero-Trust Secret Verification

The Weft server does not generally have a signed TLS certificate.  Weft uses a short AES-based challenge to verify both the server and client possess the secret to prevent clients from connecting to fake servers.

1. Client `GET`s `/login`.
2. Server generates a random nonce and returns the string "server-<nonce>" encrypted with the common secret.
3. Client decrypts and verifies that the "server-" prefix is present.
4. Client encrypts the nonce and `POST`s it to `/login`.
5. Server verifies the returned ciphertext; on success it issues a short-lived JWT (~30m).

Subsequently, the token is used for healthchecks.  When it expires, the client must repeat the challenge to obtain a new token.

Notes:
- All AES operations use the shared connection secret as the key; the nonce is single-use.
- The protocol proves knowledge of the secret both ways without exposing the secret or requiring signed certs.
- JWT is used for subsequent requests; when it expires the challenge repeats.
