<!-- docdaemon ts:2026-10-09T01:40:16Z hash:1d46ab07df92c954 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides cryptographic utilities for encrypting login challenge data and generating self-signed certificates.

### Purpose
The `crypto` package supports the server's login challenge exchange by handling symmetric encryption and certificate generation. It ensures secure communication through AES-GCM and facilitates local testing or internal service-to-service auth via generated X.509 certificates.

### Key Functions

#### `Encrypt(key, text string) ([]byte, error)`
Derives a 256-bit AES key from the input `key` string using SHA-256. It encrypts `text` using AES-GCM with a random nonce, returning the ciphertext with the nonce prepended.

#### `Decrypt(key string, ciphertext []byte) ([]byte, error)`
Reverses `Encrypt`. It derives the same AES key from `key`, extracts the nonce from the beginning of `ciphertext`, and decrypts the remaining bytes. Returns an error if the ciphertext is too short or decryption fails.

#### `GenerateCert(commonName string, additionalIps []string) ([]byte, []byte, error)`
Generates a new RSA private key (2048-bit) and a corresponding self-signed X.509 certificate. The certificate includes:
- **Subject**: Uses `commonName`.
- **Validity**: Valid for 10 years, starting 30 days in the past.
- **SANs**: Includes `commonName`, "localhost", IPv4 zero address, loopback, and any IPs provided in `additionalIps`.
- **Usage**: Server authentication.
Returns PEM-encoded certificate and private key bytes.