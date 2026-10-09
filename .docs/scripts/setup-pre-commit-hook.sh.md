<!-- docdaemon ts:2026-10-09T01:40:05Z hash:fea23d79ba8a3502 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script installs a Git pre-commit hook that ensures Bazel dependencies are up-to-date and all tests pass before allowing a commit.

### Purpose
The file automates the configuration of the `.git/hooks/pre-commit` script for the repository. It ensures that every commit adheres to project standards by running mandatory checks via Bazel.

### Key Functions
- **Hook Installation**: Creates the `.git/hooks` directory if it does not exist and writes the `pre-commit` script with executable permissions.
- **Gazelle Sync**: Runs `bazel run //:gazelle` to update BUILD files. If this command modifies any files, the hook fails, requiring the developer to stage the changes and retry the commit. This prevents drift between source code and build rules.
- **Test Validation**: Executes `bazel test //...` to run the entire test suite. The commit is blocked if any test fails.

### Integration
This script should be run once after cloning the repository or when updating the hook logic. It relies on Bazel being installed and configured in the project root.