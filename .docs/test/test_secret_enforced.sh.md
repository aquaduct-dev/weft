<!-- docdaemon ts:2026-10-09T01:40:57Z hash:00dd485c8dc283a9 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This script validates that the Weft server enforces connection secrets by verifying log output and testing tunnel connectivity with correct and incorrect credentials.

### Purpose
The file automates end-to-end testing of the `--connection-secret` feature in the Weft server. It ensures that unauthorized connections are rejected and authorized connections succeed, while confirming that secret handling is visible in server logs for debugging or auditing purposes.

### Key Functions
- **Server Initialization**: Starts the Weft server in the background using a randomly generated 32-character alphanumeric connection secret.
- **Log Verification**: Checks `server.log` to ensure the string "Connection Secret" and the specific secret value are present, validating logging behavior.
- **Unauthorized Access Test**: Attempts to establish a tunnel using a hardcoded wrong secret (`wrong-secret`). The test expects this command to fail immediately.
- **Authorized Access Test**: Establishes a tunnel using the valid generated secret. The process runs in the background, and its survival after a short sleep confirms successful authentication and tunnel setup.

### Integration
This test relies on helper functions from `lib.sh`, such as `find_free_port` for dynamic port allocation and `cleanup` for resource teardown via a trap. It uses `$WEFT_BIN` to invoke the binary under test and writes logs to `$LOGDIR`.