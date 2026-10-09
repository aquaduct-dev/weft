<!-- docdaemon ts:2026-10-09T01:40:31Z hash:954e199b251e1673 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the path-matching and prefix-stripping logic in the virtual host proxy, ensuring segment-aware routing and correct traversal normalization.

### Purpose
The tests verify that `PathMatcher` and `PathPrefixModifier` correctly handle URL segments, preventing false positives on sibling paths (e.g., `/api` should not match `/apifoo`) and normalizing path traversal sequences (e.g., `/api/../admin`) before matching or stripping.

### Key Components

*   **`TestPathMatcher_SegmentAware`**: Validates that `PathMatcher.Matches` strictly adheres to segment boundaries. It ensures that literal text prefixes do not cause matches on non-segment siblings and that normalized traversal paths are evaluated correctly against the configured prefix.
*   **`TestFindRoute_LongestPrefixWins`**: Verifies the route selection strategy in `VHostProxy.findRoute`. It confirms that among multiple routes on a single host, the longest matching path prefix takes precedence regardless of registration order. It also checks that ties fall back to registration order and that non-matching routes return `nil`.
*   **`TestPathPrefixModifier_SegmentAware`**: Ensures `PathPrefixModifier.Apply` only strips the prefix when it constitutes a full path segment. It verifies that sibling paths remain untouched and that traversal sequences are normalized so that upstream requests receive clean paths without residual traversal artifacts.