<!-- docdaemon ts:2026-10-09T01:40:51Z hash:40e0766da368b5c3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines global variables that store the build commit hash and date, defaulting to "unknown" if not stamped.

## Purpose
The `version` package provides static identifiers for the running binary. These values are injected at link time by Bazel using `x_defs` from `scripts/workspace_status.sh`. If the build is not stamped (e.g., local `go build`), the variables retain their default values.

## Variables
- **Commit**: The git commit hash associated with the build. Defaults to `"unknown"`.
- **CommitDate**: The date of the commit. Defaults to `"unknown"`.

## Usage
Access these variables directly from any package importing `github.com/your-org/repo/version` to include build metadata in logs, health checks, or API responses. No functions are exposed; this is a pure data package.