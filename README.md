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

Weft uses `wireguard-go`.  The connection secret is used to start a control tunnel to the server, which then creates additional WireGuard interfaces and replies with the connection details over the tunnel.  After that point, the client only uses the control tunnel to indicate shutdowns and perform healthchecks.  The server proxies requests back through the new Wireguard tunnels to serve requests made to the public IP.

### HTTPS Zero-Trust (concise, crypto-focused)

The Weft server does not generally have a signed TLS certificate.  Weft uses a short AES-based challenge to verify both the server and client possess the secret.

1. Client `GET`s `/login`.
2. Server generates a random nonce and returns the string "server-<nonce>" encrypted with the common secret.
3. Client decrypts and verifies that the "server-" prefix is present.
4. Client encrypts the nonce and `POST`s it to `/login`.
5. Server verifies the returned ciphertext; on success it issues a short-lived JWT (~30m).

Notes:
- All AES operations use the shared connection secret as the key; the nonce is single-use.
- The protocol proves knowledge of the secret both ways without exposing the secret or requiring signed certs.
- JWT is used for subsequent requests; when it expires the challenge repeats.
