<!-- docdaemon ts:2026-10-19T23:25:43Z hash:4eaffa11eb37e5a3 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file manages Cloudflare DNS record updates for a specific hostname.

The `UpdateRecord` function synchronizes DNS state by removing all existing records for a given hostname and creating new A and TXT records pointing to a target IP. It uses the Cloudflare API token passed as an argument to authenticate requests.

Key behaviors include:
- **Zone Resolution**: The `findZone` helper identifies the correct Cloudflare zone by matching the hostname against available zones, preferring the longest matching domain suffix (e.g., `bar.com` over `com` for `foo.bar.com`). It handles case-insensitivity and trailing dots correctly.
- **Cleanup**: Before creating new records, it deletes all pre-existing DNS records associated with the hostname, regardless of type.
- **Record Creation**: It creates an A record with a short TTL (120s) and proxy disabled, followed by a TXT record containing a timestamped update message.