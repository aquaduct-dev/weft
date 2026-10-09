<!-- docdaemon ts:2026-10-09T01:41:02Z hash:7a1bc0909126c6f6 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the Weft tunneling protocol correctly rejects connections intercepted by a Man-in-the-Middle (MITM) proxy.

It spins up a local Weft server and an `openssl`-based MITM proxy to simulate an attacker attempting to intercept traffic. The test connects a client through the fake proxy, expecting the connection to fail due to certificate verification errors. If the tunnel succeeds, the test fails, indicating a vulnerability in the encryption layer.