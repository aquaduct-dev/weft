<!-- docdaemon ts:2026-10-19T23:25:46Z hash:4a6164b2f5e1fda3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `findZone` function, which determines the correct Cloudflare zone for a given hostname.

The `TestFindZone` function validates the longest-suffix-wins logic used during record updates. It ensures that zone selection respects label boundaries (preventing `notexample.com` from matching `example.com`) and handles case insensitivity and trailing dots correctly. These checks were introduced to fix a bug where plain suffix matching caused incorrect zone associations.