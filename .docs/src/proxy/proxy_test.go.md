<!-- docdaemon ts:2026-10-09T01:40:21Z hash:74f4ec19ce045396 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains integration and unit tests for the `ProxyManager` and individual proxy types, verifying tunnel creation, traffic forwarding, conflict detection, and concurrency safety.

It validates that TCP, UDP, and HTTP tunnels correctly forward data to backends and handle edge cases like duplicate names or conflicting ports. The suite also ensures thread-safety by stressing UDP session maps under concurrent load and verifies that `Conflicts` methods accurately prevent binding collisions between different proxy implementations.