<!-- docdaemon ts:2026-10-09T01:40:06Z hash:ab939ccb36c88e65 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script generates stable Git metadata for Bazel build definitions to ensure cache-friendly incremental builds.

### Purpose
The file emits `STABLE_` prefixed environment variables consumed by Bazel's `x_defs`. These keys trigger re-linking only when their values change, preventing unnecessary rebuilds during day-to-day development without new commits.

### Key Functions
- **Commit Hash Extraction**: Retrieves the short (7-character) Git commit hash using `git rev-parse`. Falls back to `"unknown"` if Git is unavailable.
- **Committer Date Extraction**: Fetches the committer date in `YYYY-MM-DD` format via `git show`. Defaults to `"unknown"` on failure.
- **Output Generation**: Prints two key-value pairs:
  - `STABLE_GIT_COMMIT`: The current commit hash.
  - `STABLE_GIT_COMMIT_DATE`: The committer date.

### Integration
This script is referenced in `//src/version:version` to inject version information into the binary. By stabilizing these outputs, it optimizes Bazel’s caching mechanism, ensuring that builds remain fast and efficient when source code changes do not affect the Git history.