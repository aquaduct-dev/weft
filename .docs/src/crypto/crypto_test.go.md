<!-- docdaemon ts:2026-10-09T01:40:14Z hash:aaba97947db7c999 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains the Ginkgo test suite for the `crypto` package, verifying encryption, decryption, and certificate generation.

It validates the core cryptographic operations provided by `github.com/aquaduct-dev/weft/src/crypto`. The tests ensure that data can be encrypted and decrypted successfully using symmetric keys, covering various input types including empty strings and Unicode characters. It also verifies error handling for incorrect keys and corrupted ciphertexts. Additionally, it checks that the `GenerateCert` function produces valid PEM-encoded certificates and private keys.