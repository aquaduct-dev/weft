<!-- docdaemon ts:2026-10-09T01:40:05Z hash:ef9a914777e0ea1e model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the root Cobra command for the Weft CLI, handling global flag parsing and application entry point execution.

### Purpose
The `rootCmd` variable establishes the base command structure for the application. It serves as the entry point for all subcommands and manages global configuration, specifically logging verbosity.

### Key Components

#### `rootCmd`
The primary `cobra.Command` instance.
- **Use**: `weft`
- **Short Description**: Identifies the tool as a Layer 4/Layer 7 proxy built on wireguard-go.
- **PersistentPreRun**: Initializes the logging subsystem via `logging.Init()`. It checks for the global `--verbose` (or `-v`) flag. If enabled, it sets `wireguard.Verbose = true` to expose internal Wireguard logs and switches the log level to `Debug`; otherwise, it defaults to `Info`.
- **Run**: Displays the help text when executed without subcommands.

#### `init()`
Registers the persistent `--verbose` / `-v` boolean flag on `rootCmd`. This flag is available to all subcommands due to its persistent nature.

#### `Execute()`
The main entry point called by `main.go`. It executes the root command tree. If execution fails, it logs the fatal error using `zerolog` and exits with status code 1.