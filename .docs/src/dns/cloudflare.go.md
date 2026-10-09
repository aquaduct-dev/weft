<!-- docdaemon ts:2026-10-09T01:40:18Z hash:6bbae79e028e4d1f model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a function to update Cloudflare DNS records for a specific hostname.

## Purpose
The `UpdateRecord` function manages DNS entries in Cloudflare by replacing existing records with new ones and logging the change via a TXT record. It is designed to ensure that a given hostname points to a specific IP address while maintaining an audit trail.

## Key Function
### `UpdateRecord(token, hostname, targetIP)`
Updates DNS records for `hostname` to point to `targetIP`.

1. **Authentication**: Initializes the Cloudflare client using the provided API token.
2. **Zone Resolution**: Identifies the correct zone by finding the longest matching domain suffix from the list of available zones.
3. **Cleanup**: Deletes all existing DNS records (A, CNAME, etc.) associated with the exact `hostname`.
4. **Creation**:
   - Creates a new **A record** pointing to `targetIP` with a TTL of 120 seconds and proxy disabled.
   - Creates a **TXT record** containing a timestamped message indicating the update.

## Integration
This module interacts directly with the Cloudflare API v4. It requires a valid Cloudflare API token with zone edit permissions. Errors are wrapped and returned, making it suitable for use in higher-level services that handle error reporting or retries.