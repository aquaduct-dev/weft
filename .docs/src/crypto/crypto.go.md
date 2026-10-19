<!-- docdaemon ts:2026-10-19T23:25:45Z hash:6da684a2aa31c14e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides cryptographic utilities for the login challenge exchange, including symmetric encryption and self-signed certificate generation.

### Symmetric Encryption
The `Encrypt` and `Decrypt` functions use AES-256 in GCM mode to provide authenticated encryption. The input key is hashed with SHA-256 to derive a 256-bit key via the shared `newGCM` helper. Nonces are generated randomly and prepended to the ciphertext. Decryption validates the ciphertext length before processing.

### Certificate Generation
`GenerateCert` creates a self-signed X.509 certificate and RSA private key (2048-bit). It configures the certificate for server authentication (`ExtKeyUsageServerAuth`) with a validity period of approximately ten years, starting thirty days in the past. The Subject Alternative Name (SAN) extension includes the provided `commonName`, "localhost", and any valid IPs from `additionalIps`. Invalid IP strings cause an immediate error rather than silently dropping entries.