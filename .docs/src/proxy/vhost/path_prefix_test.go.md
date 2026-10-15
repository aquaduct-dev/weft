<!-- docdaemon ts:2026-10-15T20:41:52Z hash:b3ca7dc230d204a2 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `PathMatcher` and `PathPrefixModifier` types, verifying segment-aware prefix matching and path normalization logic.

### Purpose
The tests ensure that path-based routing correctly distinguishes between semantic path segments and textual prefixes. They validate fixes for issues where sibling paths (e.g., `/apifoo` vs `/api`) or traversal sequences (e.g., `/api/../admin`) incorrectly matched or modified requests.

### Key Components

*   **`TestPathMatcher_SegmentAware`**: Verifies that `PathMatcher.Matches` requires a strict segment boundary after the prefix. It confirms that `/api` does not match `/apifoo` and that URL traversal sequences are normalized before evaluation.
*   **`TestFindRoute_LongestPrefixWins`**: Validates the route selection strategy in `VHostProxy.findRoute`. It ensures that among multiple routes on a host, the longest matching prefix takes precedence regardless of registration order, while ties fall back to insertion order.
*   **`TestPathPrefixModifier_SegmentAware`**: Tests `PathPrefixModifier.Apply` to ensure it only strips the prefix if it constitutes a full segment. It also verifies that dot-segments (`.` and `..`) are normalized so upstream services receive clean paths.
*   **`TestPathPrefixModifier_RootPrefixKeepsTrailingSlash`**: Confirms that the root prefix modifier passes paths through unchanged, preserving trailing slashes to prevent redirect loops in registries.