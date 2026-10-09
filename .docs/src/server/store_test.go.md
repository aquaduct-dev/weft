<!-- docdaemon ts:2026-10-09T01:40:42Z hash:9198df4d1d520099 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains the race-condition test for `CreatePeer` to ensure IP address allocation is atomic and leak-free.

It verifies that concurrent calls to `CreatePeer` with the same tunnel name result in exactly one successful creation, where all racers observe the same peer and IP. The test ensures no IPs are leaked by checking that only the expected number of addresses (server, tunnel, and one additional free IP) remain reserved after the race completes.