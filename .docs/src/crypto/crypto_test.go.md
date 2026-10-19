<!-- docdaemon ts:2026-10-19T23:25:45Z hash:d7af7c34b6ba6022 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains the Ginkgo test suite for the `crypto` package, verifying encryption round-trips, error handling, and certificate generation logic.

The suite validates three core behaviors of the `crypto` package:

### Encrypt/Decrypt
Tests ensure that `Encrypt` and `Decrypt` correctly round-trip various inputs, including empty strings and Unicode characters. It verifies that decryption fails appropriately when provided with an incorrect key or corrupted ciphertext (e.g., flipped bytes). These checks confirm the integrity guarantees of the underlying AES-GCM implementation.

### GenerateCert
Tests validate that `GenerateCert` produces valid PEM-encoded certificates and private keys. Specifically, it ensures:
- The certificate includes the requested common name and "localhost" in its DNS Subject Alternative Names (SANs).
- Additional IP addresses passed to the function are correctly added to the IP SANs, along with standard loopback addresses (`127.0.0.1`, `::`).
- Invalid IP addresses in the input list cause the function to return an error rather than silently dropping them, ensuring callers receive feedback on configuration errors.