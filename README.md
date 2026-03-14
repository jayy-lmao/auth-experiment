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

## Quick Start

The most common production setup is **local password login that issues a JWT**, with subsequent requests authenticated by that JWT. The `harbour-axum` adapter wires this up in a few lines.

```toml
# Cargo.toml (jwt feature is on by default)
harbour-axum             = { path = "..." }
harbour-strategy-local   = { path = "...", features = ["argon2"] }
harbour-strategy-jwt     = { path = "..." }
```

```rust
use harbour_axum::HarbourAuth;
use harbour_core::Principal;
use harbour_strategy_jwt::{JwtIssuer, JwtStrategy};
use harbour_strategy_local::{
    Argon2PasswordHasher, Argon2PasswordVerifier, InMemoryUserStore, LocalStrategy,
};

let secret = b"change-me-in-production";

// Swap InMemoryUserStore for a DB-backed LocalUserStore implementation in production.
let store = InMemoryUserStore::new().with_user(
    "alice@example.com",
    Principal::new("user-1").with_name("Alice").with_role("admin"),
    Argon2PasswordHasher::hash_password("hunter2")?,
);

// Login route: verify credentials and respond with {"access_token": "..."}
let login_auth = HarbourAuth::new("local", LocalStrategy::new(store, Argon2PasswordVerifier))
    .with_jwt_issuer(JwtIssuer::hs256(secret));

// Protected routes: verify the JWT on every request
let api_auth = HarbourAuth::new("jwt", JwtStrategy::hs256(secret));
```

- **`POST /login`** — apply `require_auth` with `login_auth`. On success the response body contains `{"access_token": "..."}`.
- **Protected routes** — apply `require_auth` with `api_auth`.
- String strategy names (`"local"`, `"jwt"`) are fine for small/single-file setups. For larger codebases a type-safe enum is preferred — see the [JWT strategy section](#jwt-strategy) below.

Tokens default to 1-hour expiry. Override when needed:

```rust
JwtIssuer::hs256(secret).with_expiry(7 * 24 * 3600) // 7 days
```

### RS256 variant (asymmetric key pair)

```rust
// Load PEM files from disk (or environment / secrets manager).
let private_pem = std::fs::read("private.pem")?;
let public_pem  = std::fs::read("public.pem")?;

// Login service: sign tokens with the private key.
let login_auth = HarbourAuth::new("local", LocalStrategy::new(store, Argon2PasswordVerifier))
    .with_jwt_issuer(JwtIssuer::rs256(&private_pem)?);

// Any service: verify tokens with the public key.
let api_auth = HarbourAuth::new("jwt", JwtStrategy::rs256(&public_pem)?);
```

---

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

`JwtStrategy` verifies `Authorization: Bearer <token>` headers. `JwtIssuer` signs tokens for login endpoints. They are separate types because in a multi-service setup the signing key (private) lives only in the login service, while the verification key (public) is shared across all services.

Every strategy implements `strategy_name()` and is self-identifying — no separate name argument needed:

```rust
use harbour_axum::HarbourAuth;
use harbour_strategy_jwt::{JwtIssuer, JwtStrategy};
use harbour_core::Principal;

let secret = b"super-secret-key";

// JwtStrategy knows its own name ("jwt") — pass it directly:
let auth = HarbourAuth::new(JwtStrategy::hs256(secret));

// Issue a token (e.g. from a login handler):
let issuer = JwtIssuer::hs256(secret); // 1-hour expiry by default
let token = issuer.issue(&Principal::new("user-123").with_name("Alice").with_role("editor"))?;
```

When you need to register multiple instances of the same strategy type under different names, use `with_strategy_named`:

```rust
// Two JWT strategies for different audiences — explicit names needed:
let auth = HarbourAuth::new(LocalStrategy::new(store, verifier))
    .with_strategy_named("jwt-internal", JwtStrategy::hs256(internal_secret))
    .with_strategy_named("jwt-external", JwtStrategy::hs256(external_secret));
```

Use `with_active_strategy` with a type-safe enum to select a per-route strategy without string literals scattered through the codebase:

```rust
use harbour_core::StrategyName;

// Enum only needed for per-route selection (with_active_strategy),
// not for registration — strategies register themselves by name.
enum AppStrategy { Internal, External }

impl StrategyName for AppStrategy {
    fn strategy_name(&self) -> &str {
        match self {
            Self::Internal => "jwt-internal",
            Self::External => "jwt-external",
        }
    }
}
```

### Third-party and custom strategies

`Strategy` is a public async trait — any crate can implement it, add a `strategy_name()` method, and pass the result straight to `HarbourAuth::new` / `with_strategy` with no changes to the core. For example, a community `harbour-strategy-google` crate would expose a `GoogleOAuthStrategy` and consumers would wire it in exactly like the built-in strategies:

```rust
// Hypothetical third-party strategy — same pattern as any other:
let auth = HarbourAuth::new(GoogleOAuthStrategy::new(client_id, client_secret))
    .with_strategy(LocalStrategy::new(store, Argon2PasswordVerifier));
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
