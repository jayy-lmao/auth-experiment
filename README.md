# Harbour MVP

Harbour is a framework-agnostic authentication library for Rust APIs.

This repository contains the smallest useful slice of that vision:

- `harbour-core`: core auth types and strategy interface (framework-agnostic)
- `harbour-axum`: Axum adapter with middleware + extractors
- `harbour-strategy-local`: extensible local identifier/password strategy

## Included strategies

- `StaticBearerStrategy` in `harbour-core`
  - checks `Authorization: Bearer <token>`
  - deterministic and in-memory
- `LocalStrategy` in `harbour-strategy-local`
  - checks `local.identifier` + `local.password`
  - supports pluggable `LocalUserStore` + `PasswordVerifier` implementations
  - includes `InMemoryUserStore` and `PlaintextPasswordVerifier` for tests/examples

## Axum usage shape

- create `HarbourAuth` with a default strategy name and strategy implementation
- optionally register additional named strategies via `with_strategy`
- apply `require_auth` middleware on protected routes
- extract `AuthPrincipal` in protected handlers
- use `MaybeAuthPrincipal` for endpoints that can be anonymous
- choose route-level strategy by applying route-level middleware that calls `middleware_with_strategy`
- optionally customize failed-auth response with `with_unauthorized_response`
- adapter maps request data into context keys:
  - `Authorization: Bearer <token>` → `bearer_token`
  - JSON body field `username` → `local.identifier`
  - JSON body field `password` → `local.password`

## Comparison with PassportJS Local Strategy

### How does Harbour's local strategy align with PassportJS Local?

Harbour's Axum adapter now reads local credentials from the **JSON request body** using the field names `username` and `password` — the same defaults as PassportJS Local Strategy (`passport-local`). The login endpoint is a `POST` route, matching the conventional PassportJS pattern.

The term "identifier" is used internally (rather than "username") to signal that it can be an email, phone number, or any unique handle, not just a traditional username. This is a naming detail that is invisible to the HTTP client.

### Similarities in usage / behaviour / developer experience

| Aspect | PassportJS Local | Harbour LocalStrategy |
|---|---|---|
| Credential transport | POST request **body** (`username`/`password` JSON fields) | POST request **body** (`username`/`password` JSON fields) |
| Credential model | identifier + password (configurable field names) | identifier + password |
| Per-route strategy selection | `passport.authenticate('local')` as middleware | `middleware_with_strategy(req, next, Some("local"))` |
| Optional (anonymous-friendly) routes | `passport.authenticate('local', { session: false })` without failing | `MaybeAuthPrincipal` extractor |
| Pluggable user lookup | verify callback provided by the developer | `LocalUserStore` trait implementation |
| Multiple strategies registered | `passport.use('admin', new LocalStrategy(...))` | `.with_strategy("admin", LocalStrategy::new(...))` |
| Invalid credentials → 401 | `done(null, false)` in verify callback | `Err(AuthError::InvalidCredentials)` |

### Remaining differences in usage / behaviour / developer experience

| Aspect | PassportJS Local | Harbour LocalStrategy |
|---|---|---|
| **Session management** | Sessions on by default (call `passport.authenticate('local', { session: false })` to disable); built-in serialisation/deserialisation for cookie-backed flows | No session layer; every request is independently authenticated — idiomatic for token-based (JWT) APIs |
| **Post-auth flow** | `req.user` populated for the request; persists across requests when sessions are enabled, request-scoped only when `session: false` | `AuthPrincipal` extractor available only within that request; no persistence |
| **Extensibility model** | Single verify callback `(username, password, done)` | Separate `LocalUserStore` trait (lookup) + `PasswordVerifier` trait (hashing), each independently swappable |
| **Framework coupling** | Tightly tied to Express/Connect middleware chain | Framework-agnostic core; Axum is just one adapter |
| **Error surfacing** | Errors passed to `done(err)` bubble through Express error middleware | Typed `AuthError` enum; strategies return `Result<Principal, AuthError>` |
| **Custom 401 body** | Requires custom `failWithError` option or a custom callback | First-class `with_unauthorized_response` builder method |

## Why this structure

- Core auth logic is independent from Axum
- Axum crate provides integration-specific concerns
- Strategy registry in core leaves a clean seam for multiple providers
- Local strategy trait seams allow plugging Postgres/SQLite/Redis-backed patterns
- Additional frameworks can be added as separate adapter crates later
