<!-- docdaemon ts:2026-10-09T01:40:26Z hash:c4172cfe2e7c69ff model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides a custom `http.ErrorLog` writer that routes net/http error messages through zerolog, distinguishing between noisy TLS handshake failures and other server errors.

## Purpose
The `httpErrorLogWriter` implements the `io.Writer` interface to intercept unstructured error lines from Go’s `net/http` server. It prevents log spam from constant TLS handshake errors (common on internet-exposed ports) by logging them at the debug level, while surfacing all other HTTP server errors as warnings for visibility.

## Key Components

### `type httpErrorLogWriter`
A struct holding the port number associated with the HTTP server instance. This allows contextual logging of which listener generated the error.

### `func (w *httpErrorLogWriter) Write(p []byte) (int, error)`
The core logic that processes each error line:
1. Trims trailing newlines from the input byte slice.
2. Checks if the line starts with `"http: TLS handshake error from "`.
3. If it is a TLS handshake error, logs it at **Debug** level with the port and full line content.
4. For any other error, logs it at **Warn** level.
5. Returns the length of the original payload and `nil` error to satisfy the `io.Writer` contract.

## Integration
This writer is assigned to `http.Server.ErrorLog` during server initialization in the vhost package. By doing so, it ensures that all low-level network errors are structured and filtered appropriately before reaching the standard logger or stderr.