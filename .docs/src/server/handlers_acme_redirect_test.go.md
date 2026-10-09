<!-- docdaemon ts:2026-10-09T01:40:33Z hash:a5e6bb5e4a3f5f57 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the ACME redirect handler, verifying request validation and DNS-based peer authorization.

It ensures `ACMERedirectHandler` correctly rejects invalid HTTP methods, missing parameters, and unauthorized peers by checking their IP against a stubbed DNS lookup. The `recordingDataplane` struct captures calls to `RegisterACMERedirect` to assert that registration only occurs when the sender's IP is found in the target host's DNS records.