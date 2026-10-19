<!-- docdaemon ts:2026-10-19T23:27:10Z hash:d83af3707ebc5a6f model:openrouter/qwen/qwen3.7-flash -->
# src/crypto

## TL;DR
This package provides cryptographic utilities for login challenge exchanges, including authenticated encryption and self-signed certificate generation.

## Overview
The `crypto` directory implements core security primitives required by the Weft project to establish secure communication channels. It abstracts away complex cryptographic operations into simple, safe-to-use functions for encrypting data and generating temporary certificates. These tools are essential for the initial handshake phase where clients and servers must verify identity and exchange secrets securely.

## Deep Dive
### Symmetric Encryption
The package exposes `Encrypt` and `Decrypt` functions that utilize AES-256 in Galois/Counter Mode (GCM). This mode provides both confidentiality and integrity, ensuring that ciphertext cannot be tampered with without detection. To derive a consistent 256-bit key from user-provided inputs, the implementation hashes the input using SHA-256 via a shared `newGCM` helper. Nonces are generated randomly for each encryption operation and prepended to the resulting ciphertext, allowing decryption to extract the correct nonce automatically. Decryption validates the total length of the input before processing to prevent malformed data attacks.

### Certificate Generation
`GenerateCert` creates self-signed X.509 certificates paired with 2048-bit RSA private keys. These certificates are configured for server authentication and have a validity period of approximately ten years, starting thirty days in the past to account for clock skew. The Subject Alternative Name (SAN) extension is populated with the provided common name, "localhost", and any additional IP addresses specified by the caller. Crucially, the function rejects invalid IP strings immediately rather than silently dropping them, ensuring callers receive explicit feedback on configuration errors. This strict validation prevents subtle misconfigurations that could lead to connection failures or security warnings.

## Key Interfaces
*   `func Encrypt(key []byte, plaintext []byte) ([]byte, error)`
*   `func Decrypt(key []byte, ciphertext []byte) ([]byte, error)`
*   `func GenerateCert(commonName string, additionalIps []string) (*x509.Certificate, *rsa.PrivateKey, error)`

## Dependencies
*   `golang.org/x/crypto` (implied by GCM usage)
*   `crypto/tls`
*   `crypto/x509`
*   `crypto/rand`
*   `crypto/sha256`
*   `crypto/aes`
*   `github.com/onsi/ginkgo/v2` (test framework)
*   `github.com/onsi/gomega` (test assertions)

## Subcomponents
*   `BUILD.bazel`: Build rules for the library and tests.
*   `crypto.go`: Core implementation of encryption and certificate logic.
*   `crypto_test.go`: Ginkgo test suite verifying round-trips and error handling.