<!-- docdaemon ts:2026-10-09T01:40:44Z hash:b734679f411a090d model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file provides middleware and helper utilities for validating JWT tokens and extracting user identity from HTTP requests.

### Purpose
The `server` package uses this file to enforce authentication on protected routes and to access authenticated user claims in downstream handlers. It bridges the gap between raw HTTP headers and typed context values.

### Key Components

#### Middleware: `requireJWT`
Attached to `*Server`, this middleware intercepts incoming requests to verify authentication.
1.  Extracts the `Authorization` header.
2.  Validates the format is `Bearer <token>`.
3.  Calls `s.ValidateJWT` to verify signature and expiration.
4.  Stores the validated `*jwt.Token` in the request context under `jwtTokenKey`.
5.  Returns a `401 Unauthorized` error if validation fails or the header is missing/invalid.

#### Context Helpers
These functions retrieve data stored by `requireJWT`:
-   **`getJWTFromContext`**: Retrieves the raw `*jwt.Token` from the context. Returns `nil` if absent.
-   **`getJWTSubject`**: Extracts the `sub` (subject) claim from the token as a string. Returns an empty string if the token or claim is missing.
-   **`getJWTSubjectFromRequest`**: A convenience wrapper that calls `getJWTSubject` using the request's context.

### Usage
Apply `requireJWT` to specific routes to ensure only authenticated users can access them. Use `getJWTSubjectFromRequest` within those handlers to identify the current user via their subject ID.