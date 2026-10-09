<!-- docdaemon ts:2026-10-09T01:40:35Z hash:9023cfd475bcfec1 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the server's authentication handler, verifying challenge-response logic, JWT validation, and memory safety constraints.

It ensures that `getChallenge` correctly manages an expiring map of challenges with bounded capacity and garbage collection. It validates that `verifyChallenge` properly handles decryption failures, consumes valid challenges, and rejects stale entries. The tests also enforce strict JWT policies: rejecting tokens from foreign issuers, ensuring no `aud` claim is present, and preventing replay attacks via `iat` skew checks. These tests support features F-1 (bounded challenge storage) and F-8 (JWT hardening).