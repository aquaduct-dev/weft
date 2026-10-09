<!-- docdaemon ts:2026-10-09T01:40:04Z hash:8632e4b212e47001 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file serves as the entry point for the application, initializing and executing the command-line interface.

### Purpose
The `main` package defines the program's starting point. It imports the `cmd` package from the `github.com/aquaduct-dev/weft` module and delegates execution to it. This structure separates the bootstrap logic from the core command handling, allowing the CLI implementation to reside in a dedicated sub-package.

### Key Components
- **`main()`**: The standard Go entry function. It calls `cmd.Execute()`, which is responsible for parsing arguments, setting up the root command, and running the application logic.

### Integration
This file acts as the bridge between the Go runtime and the Weft CLI framework. All business logic, flags, and subcommands are defined within the `cmd` package, keeping this file minimal and focused on initialization.