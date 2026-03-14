# Harbour MVP

Harbour is a framework-agnostic authentication library for Rust APIs.

This repository contains the smallest useful slice of that vision:

- `harbour-core`: core auth types and strategy interface (framework-agnostic)
- `harbour-axum`: Axum adapter with middleware + extractors
- `harbour-strategy-local`: extensible local identifier/password strategy with optional Argon2 password hashing
- `harbour-strategy-jwt`: JWT Bearer token strategy with issuance and verification

## Included strategies

- `StaticBearerStrategy` in `harbour-core`
  - checks `Authorization: Bearer <token>`
  - deterministic and in-memory
- `LocalStrategy` in `harbour-strategy-local`
  - checks `local.identifier` + `local.password`
  - supports pluggable `LocalUserStore` + `PasswordVerifier` implementations
  - includes `InMemoryUserStore` and `PlaintextPasswordVerifier` for tests/examples
  - includes `Argon2PasswordVerifier` + `Argon2PasswordHasher` (enable the `argon2` feature) for production use
- `JwtStrategy` in `harbour-strategy-jwt`
  - verifies `Authorization: Bearer <jwt>` headers
  - supports HS256 (shared secret) and RS256 (RSA key pair) algorithms
  - pairs with `JwtIssuer` for token generation in login handlers

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

## Production password hashing (Argon2)

Enable the `argon2` feature on `harbour-strategy-local` to unlock production-grade password hashing:

```toml
harbour-strategy-local = { path = "...", features = ["argon2"] }
```

```rust
use harbour_strategy_local::{Argon2PasswordHasher, Argon2PasswordVerifier, InMemoryUserStore, LocalStrategy};

// At registration time — hash and store the password:
let hash = Argon2PasswordHasher::hash_password("hunter2")?;

// Build the strategy — verify using Argon2id:
let strategy = LocalStrategy::new(
    InMemoryUserStore::new().with_user("alice", principal, hash),
    Argon2PasswordVerifier,
);
```

## JWT strategy

```rust
use harbour_core::{Principal, StrategyName};
use harbour_strategy_jwt::{JwtIssuer, JwtStrategy};

// Use a type-safe strategy enum (preferred over bare strings).
enum AppStrategy { Jwt, Local }

impl StrategyName for AppStrategy {
    fn strategy_name(&self) -> &str {
        match self {
            Self::Jwt   => "jwt",
            Self::Local => "local",
        }
    }
}

let secret = b"super-secret-key";

// Issue a JWT in a login handler:
let issuer = JwtIssuer::hs256(secret, 3600 /* expiry seconds */);
let token = issuer.issue(&Principal::new("user-123").with_name("Alice").with_role("editor"))?;

// Protect routes with JwtStrategy — strategy name comes from the enum, not a bare string:
let auth = HarbourAuth::new(AppStrategy::Jwt, JwtStrategy::hs256(secret));
```

## Role-based access control (RBAC)

`Principal` now carries a `roles` field, populated from the `LocalUserStore` or from JWT claims:

```rust
use harbour_core::Principal;

let p = Principal::new("user-1").with_role("admin").with_role("editor");
assert!(p.has_role("admin"));
assert!(!p.has_role("viewer"));
```

In a handler, gate access by role after extracting the principal:

```rust
async fn admin_only(AuthPrincipal(p): AuthPrincipal) -> impl IntoResponse {
    if !p.has_role("admin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    // ...
}
```

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
| Password hashing | `bcrypt` via third-party libs | `Argon2PasswordVerifier` / `Argon2PasswordHasher` (feature flag) |
| JWT Bearer auth | `passport-jwt` package | `harbour-strategy-jwt` crate |
| Role/claims-based access | `req.user.roles` populated by verify callback | `Principal::roles` + `Principal::has_role()` |

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
