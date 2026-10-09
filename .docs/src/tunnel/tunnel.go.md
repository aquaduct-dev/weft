<!-- docdaemon ts:2026-10-09T01:40:49Z hash:e21e40f6988b7623 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file implements the `Tunnel` function to establish a client-side WireGuard connection and associated proxy based on server response data.

The `Tunnel` function orchestrates the creation of a userspace WireGuard device. It parses the assigned client IP from the `ConnectResponse`, resolves the server address, and constructs a WireGuard configuration using the provided private key and server public key. After initializing the device, it builds the remote URL for the tunnel proxy and starts the proxy manager. Helper functions handle IP resolution, WireGuard config generation, and URL construction logic specific to different protocols (TCP, HTTP, HTTPS, UDP).