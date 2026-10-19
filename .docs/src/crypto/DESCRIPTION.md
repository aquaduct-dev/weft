<!-- docdaemon ts:2026-10-09T01:41:56Z hash:a43ba64810b17ebb model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `crypto` package provides symmetric encryption utilities and self-signed certificate generation for secure communication and testing.

## Overview
This directory implements core cryptographic functions required by the Weft server, specifically focusing on login challenge exchanges and internal service authentication. It abstracts away the complexity of AES-GCM encryption and X.509 certificate creation, offering a simple API for developers. The library ensures data confidentiality through robust symmetric encryption and facilitates local development via automated certificate generation.

## Deep Dive
### Symmetric Encryption
The package exposes `Encrypt` and `Decrypt` functions that handle AES-256-GCM operations. To ensure compatibility with string-based inputs, the input key is hashed using SHA-256 to derive a fixed 256-bit AES key. Encryption prepends a random nonce to the ciphertext, allowing decryption to extract it automatically. This design simplifies usage while maintaining security standards against replay attacks.

### Certificate Generation
For scenarios requiring mutual TLS or local testing, `GenerateCert` creates self-signed X.509 certificates. It generates a 2048-bit RSA private key and a corresponding certificate valid for ten years. The certificate Subject Alternative Names (SANs) are automatically populated: the DNS names are `commonName` and "localhost", and the IP addresses are any user-provided IPs plus the IPv4 zero address and 127.0.0.1. A user-provided entry that is not a valid IP makes `GenerateCert` return an error. This automation reduces boilerplate code when setting up secure local environments.

## Key Interfaces
*   `func Encrypt(key, text string) ([]byte, error)`
*   `func Decrypt(key string, ciphertext []byte) ([]byte, error)`
*   `func GenerateCert(commonName string, additionalIps []string) ([]byte, []byte, error)`

## Dependencies
*   `github.com/aquaduct-dev/weft/src/crypto` (internal import path)
*   `golang.org/x/crypto` (standard Go crypto libraries)
*   `github.com/onsi/ginkgo/v2` (testing framework)
*   `github.com/onsi/gomega` (testing assertions)

## Subcomponents
*   `BUILD.bazel`: Bazel build configuration for the library and tests.
*   `crypto.go`: Implementation of encryption and certificate generation logic.
*   `crypto_test.go`: Ginkgo test suite covering encryption round-trips and cert validity.