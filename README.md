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
- adapter currently maps headers into context keys:
  - `Authorization: Bearer ...` -> `bearer_token`
  - `x-auth-identifier` -> `local.identifier`
  - `x-auth-password` -> `local.password`

## Comparison with PassportJS Local Strategy

### Is the `x-auth-identifier` / `x-auth-password` pattern the same as PassportJS Local?

No. PassportJS Local Strategy (`passport-local`) reads credentials from the **request body** — typically form fields or a JSON body — using field names `username` and `password` (both configurable). It does **not** use custom HTTP headers.

Harbour's Axum adapter maps `x-auth-identifier` and `x-auth-password` **request headers** into the auth context, then passes them into the `LocalStrategy`. The credential transport mechanism is therefore different. The term "identifier" is also used instead of "username" to signal that it can be an email, phone number, or any unique handle, not just a traditional username.

### Similarities in usage / behaviour / developer experience

| Aspect | PassportJS Local | Harbour LocalStrategy |
|---|---|---|
| Credential model | identifier + password (configurable field names) | identifier + password |
| Per-route strategy selection | `passport.authenticate('local')` as middleware | `middleware_with_strategy(req, next, Some("local"))` |
| Optional (anonymous-friendly) routes | `passport.authenticate('local', { session: false })` without failing | `MaybeAuthPrincipal` extractor |
| Pluggable user lookup | verify callback provided by the developer | `LocalUserStore` trait implementation |
| Multiple strategies registered | `passport.use('admin', new LocalStrategy(...))` | `.with_strategy("admin", LocalStrategy::new(...))` |
| Invalid credentials → 401 | `done(null, false)` in verify callback | `Err(AuthError::InvalidCredentials)` |

### Differences in usage / behaviour / developer experience

| Aspect | PassportJS Local | Harbour LocalStrategy |
|---|---|---|
| **Credential transport** | Request **body** (form or JSON fields) | Custom **request headers** (`x-auth-identifier`, `x-auth-password`) |
| **Session management** | Built-in session serialisation/deserialisation; issues a session cookie after successful login by default | No session layer in this MVP; every request must supply credentials in headers |
| **Post-auth flow** | `req.user` populated; session persists across requests | `AuthPrincipal` extractor available only within that request; no persistence |
| **Extensibility model** | Single verify callback `(username, password, done)` | Separate `LocalUserStore` trait (lookup) + `PasswordVerifier` trait (hashing), each independently swappable |
| **Framework coupling** | Tightly tied to Express/Connect middleware chain | Framework-agnostic core; Axum is just one adapter |
| **Error surfacing** | Errors passed to `done(err)` bubble through Express error middleware | Typed `AuthError` enum; strategies return `Result<Principal, AuthError>` |
| **Custom 401 body** | Requires custom `failWithError` option or a custom callback | First-class `with_unauthorized_response` builder method |

The most consequential behavioral difference for client developers is credential transport: a PassportJS local auth endpoint expects a `POST` with a body (`application/json` or `application/x-www-form-urlencoded`), while Harbour's current Axum adapter expects headers on any HTTP method. A production Harbour adapter would likely want to support body-field extraction as an alternative or preferred transport to align more closely with conventional login endpoints.

## Why this structure

- Core auth logic is independent from Axum
- Axum crate provides integration-specific concerns
- Strategy registry in core leaves a clean seam for multiple providers
- Local strategy trait seams allow plugging Postgres/SQLite/Redis-backed patterns
- Additional frameworks can be added as separate adapter crates later
