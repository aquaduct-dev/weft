<!-- docdaemon ts:2026-10-09T01:41:02Z hash:ff12f2c8ab8f2882 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script verifies that the weft tunnel correctly defaults to port 80 when the remote target URL omits an explicit port number.

### Purpose
The file performs an end-to-end integration test for the `weft` CLI tool. It ensures that HTTP traffic routed through a tunnel respects standard port conventions, specifically handling cases where the destination URL lacks a port specification.

### Key Components
- **Server Setup**: Starts a local `weft server` instance on a dynamically allocated free port and waits for the authentication secret file to be generated.
- **Tunnel Configuration**: Initiates a tunnel connecting a local backend (`http://127.0.0.1`) to a remote target (`http://localhost:23422`). The test logic relies on the absence of a port in the target URL to trigger default behavior.
- **Validation**: Checks the tunnel log for successful proxy initialization. If the proxy fails to start, it dumps server and tunnel logs for debugging before exiting with an error code.

### Integration
This test is part of the broader test suite defined in `lib.sh`. It depends on the `WEFT_BIN` environment variable pointing to the compiled binary and uses helper functions like `find_free_port`, `wait_for_port`, and `cleanup` to manage resources and lifecycle.