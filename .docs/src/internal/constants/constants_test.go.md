<!-- docdaemon ts:2026-10-19T23:25:47Z hash:54aa493e05ad8a9f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains tests to ensure that pre-parsed network address constants remain consistent with their string representations and logical constraints.

The `TestParsedValuesMatchStrings` function validates the integrity of the `DefaultSubnet` and `DefaultServerIP` constants. It performs three checks:
1. Verifies that `DefaultSubnet.String()` matches the expected `DefaultSubnetString`.
2. Verifies that `DefaultServerIP.String()` matches the expected `DefaultServerIPString`.
3. Confirms that `DefaultServerIP` is contained within `DefaultSubnet`.

These assertions catch typos in either the parsed values or their string counterparts before runtime, preventing configuration errors at startup. The test was introduced after removing unused constants to focus on verifying these core network defaults.