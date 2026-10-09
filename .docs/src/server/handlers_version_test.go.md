<!-- docdaemon ts:2026-10-09T01:40:39Z hash:2da4ff9587a40287 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains the unit tests for the `VersionHandler` HTTP handler.

It verifies that the `/version` endpoint correctly returns a `200 OK` status and a JSON body containing the application's build commit hash and date. The test ensures the response `Content-Type` is set to `application/json` and validates that the returned values match the constants defined in the `version` package. This serves as the primary regression check for the version information API contract.