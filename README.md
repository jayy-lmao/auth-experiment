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

## Why this structure

- Core auth logic is independent from Axum
- Axum crate provides integration-specific concerns
- Strategy registry in core leaves a clean seam for multiple providers
- Local strategy trait seams allow plugging Postgres/SQLite/Redis-backed patterns
- Additional frameworks can be added as separate adapter crates later
