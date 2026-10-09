<!-- docdaemon ts:2026-10-09T01:41:53Z hash:7d4f47c4fa9d1067 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
The `dns` directory provides a Go library for managing Cloudflare DNS records with structured logging.

## Overview
This module serves as the DNS abstraction layer for the Weft project, isolating Cloudflare-specific logic to allow consistent interaction with DNS services. It ensures that hostnames point to specific IP addresses while maintaining an audit trail through TXT records. The library leverages the Cloudflare Go SDK and Zerolog for reliable API communication and structured logging.

## Deep Dive
### Cloudflare Integration
The core functionality resides in `cloudflare.go`, which implements the `UpdateRecord` function. This function authenticates with Cloudflare using an API token and resolves the correct zone by finding the longest matching domain suffix. It then performs a cleanup phase, deleting all existing A and CNAME records associated with the target hostname to prevent conflicts. Finally, it creates a new A record pointing to the specified IP address with a 120-second TTL and proxy disabled. To maintain an audit trail, it also creates a TXT record containing a timestamped message indicating the update action.

### Error Handling and Logging
Errors from the Cloudflare API are wrapped and returned, allowing higher-level services to handle retries or reporting appropriately. Structured logging is handled via Zerolog, ensuring that DNS operations are traceable within the application's logs.

## Key Interfaces
- `UpdateRecord(token, hostname, targetIP)`: Updates DNS records for a hostname to point to a target IP.

## Dependencies
- Cloudflare Go SDK: Provides the underlying client for interacting with Cloudflare's DNS API.
- Zerolog: Used for structured logging within the DNS module.

## Subcomponents
- `BUILD.bazel`: Defines the Bazel build rules for the `dns` Go library.
- `cloudflare.go`: Implements the logic for updating Cloudflare DNS records.