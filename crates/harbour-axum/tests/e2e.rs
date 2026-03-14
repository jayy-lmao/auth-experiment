use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use harbour_axum::{require_auth, AuthPrincipal, HarbourAuth, MaybeAuthPrincipal};
use harbour_core::{Principal, StaticBearerStrategy, StrategyName};
use harbour_strategy_jwt::{JwtIssuer, JwtRefreshStrategy, JwtStrategy};
use harbour_strategy_local::{InMemoryUserStore, LocalStrategy, PlaintextPasswordVerifier};
use tower::ServiceExt;

/// Application-defined strategy enum — used with `with_active_strategy` to select a
/// per-route strategy without repeating the string name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppStrategy {
    Admin,
    Local,
}

impl StrategyName for AppStrategy {
    fn strategy_name(&self) -> &str {
        match self {
            Self::Admin => "admin",
            Self::Local => "local",
        }
    }
}

fn auth_config() -> HarbourAuth {
    // Strategies are self-identifying — no separate name argument needed at registration.
    // StaticBearerStrategy::named gives the instance its name when the same type is used
    // multiple times ("user" and "admin" both use StaticBearerStrategy with different tokens).
    HarbourAuth::new(StaticBearerStrategy::named(
        "user",
        "top-secret-token",
        Principal::new("user-123").with_name("Demo User"),
    ))
    .with_strategy(StaticBearerStrategy::named(
        "admin",
        "admin-token",
        Principal::new("admin-999").with_name("Admin User"),
    ))
    .with_strategy(LocalStrategy::new(
        InMemoryUserStore::new().with_user(
            "alice",
            Principal::new("local-1").with_name("Alice Local"),
            "password123",
        ),
        PlaintextPasswordVerifier,
    ))
}

fn protected_app() -> Router {
    let auth = auth_config();

    let protected = Router::new()
        .route("/protected", get(protected_handler))
        .route("/also-protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth));

    // Use `with_active_strategy` + `require_auth` to select a per-route strategy.
    let admin = Router::new().route(
        "/admin",
        get(admin_handler).route_layer(middleware::from_fn_with_state(
            auth.clone().with_active_strategy(AppStrategy::Admin),
            require_auth,
        )),
    );

    let local = Router::new().route(
        "/login-local",
        post(local_handler).route_layer(middleware::from_fn_with_state(
            auth.clone().with_active_strategy(AppStrategy::Local),
            require_auth,
        )),
    );

    let unknown_strategy = Router::new().route(
        "/unknown-strategy",
        get(protected_handler).route_layer(middleware::from_fn_with_state(
            auth.clone().with_active_strategy("does-not-exist"),
            require_auth,
        )),
    );

    protected
        .merge(admin)
        .merge(local)
        .merge(unknown_strategy)
        .with_state(auth)
}

fn custom_unauthorized_app() -> Router {
    let auth = auth_config().with_unauthorized_response(|| {
        (StatusCode::UNAUTHORIZED, "custom unauthorized").into_response()
    });

    Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth))
        .with_state(auth)
}

fn optional_app() -> Router {
    Router::new().route("/optional", get(optional_handler))
}

async fn protected_handler(AuthPrincipal(principal): AuthPrincipal) -> impl IntoResponse {
    format!("{}:{}", principal.id, principal.name.unwrap_or_default())
}

async fn admin_handler(AuthPrincipal(principal): AuthPrincipal) -> impl IntoResponse {
    format!("admin:{}", principal.id)
}

async fn local_handler(AuthPrincipal(principal): AuthPrincipal) -> impl IntoResponse {
    format!("local:{}", principal.id)
}

async fn optional_handler(MaybeAuthPrincipal(principal): MaybeAuthPrincipal) -> impl IntoResponse {
    principal
        .map(|p| p.id)
        .unwrap_or_else(|| "anonymous".to_string())
}

#[tokio::test]
async fn no_auth_header_returns_401() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_bearer_token_returns_401() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_authorization_header_returns_401() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "NotBearer token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_bearer_token_returns_200_and_principal_is_available() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Bearer top-secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"user-123:Demo User");
}

#[tokio::test]
async fn second_route_is_protected_too() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/also-protected")
                .header("authorization", "Bearer top-secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_unauthorized_response_is_returned() {
    let response = custom_unauthorized_app()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"custom unauthorized");
}

#[tokio::test]
async fn optional_extractor_returns_anonymous_without_auth() {
    let response = optional_app()
        .oneshot(
            Request::builder()
                .uri("/optional")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"anonymous");
}

#[tokio::test]
async fn optional_extractor_returns_principal_when_present() {
    let auth = auth_config();
    let app = Router::new()
        .route("/optional", get(optional_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth))
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/optional")
                .header("authorization", "Bearer top-secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"user-123");
}

#[tokio::test]
async fn route_can_select_different_strategy() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header("authorization", "Bearer admin-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"admin:admin-999");
}

#[tokio::test]
async fn unknown_route_strategy_returns_401() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/unknown-strategy")
                .header("authorization", "Bearer top-secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn local_strategy_authenticates_from_json_body() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login-local")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"alice","password":"password123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"local:local-1");
}

#[tokio::test]
async fn local_strategy_rejects_bad_password() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login-local")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"alice","password":"wrong"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── Shortcoming 1: with_active_strategy (enum-based, no verbose closure) ────────────────────────

#[tokio::test]
async fn with_active_strategy_uses_named_strategy() {
    // Demonstrates that with_active_strategy + require_auth eliminates the verbose closure.
    let auth = auth_config();

    let app = Router::new()
        .route(
            "/admin",
            get(admin_handler).route_layer(middleware::from_fn_with_state(
                auth.clone().with_active_strategy(AppStrategy::Admin),
                require_auth,
            )),
        )
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header("authorization", "Bearer admin-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"admin:admin-999");
}

// ── Shortcoming 2: on_authenticated hook for post-auth response transformation ──────────────────

#[tokio::test]
async fn on_authenticated_hook_can_add_response_header() {
    let auth = auth_config().with_on_authenticated(|principal, mut response| {
        let header_value = format!("token-for-{}", principal.id);
        response.headers_mut().insert(
            "x-auth-token",
            header_value.parse().unwrap(),
        );
        response
    });

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth))
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Bearer top-secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-auth-token").unwrap(),
        "token-for-user-123"
    );
}

#[tokio::test]
async fn on_authenticated_hook_is_not_called_on_failed_auth() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let hook_called = Arc::new(AtomicBool::new(false));
    let hook_called_clone = Arc::clone(&hook_called);

    let auth = auth_config().with_on_authenticated(move |_principal, response| {
        hook_called_clone.store(true, Ordering::SeqCst);
        response
    });

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth))
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!hook_called.load(Ordering::SeqCst));
}

// ── Shortcoming 3: body only buffered for JSON requests ──────────────────────────────────────────

#[tokio::test]
async fn bearer_route_does_not_require_json_body() {
    // Validates that a bearer-authenticated route is not broken by the
    // "skip body buffering when no JSON content-type" optimisation.
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Bearer top-secret-token")
                // Deliberately no Content-Type header — body buffering must be skipped.
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn local_strategy_without_json_content_type_returns_401() {
    // Without Content-Type: application/json the body is not parsed, so credentials
    // are never extracted and the request is correctly rejected.
    let response = protected_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login-local")
                // No content-type header — body is not read.
                .body(Body::from(r#"{"username":"alice","password":"password123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── Shortcoming 4: configurable JSON field names ─────────────────────────────────────────────────

#[tokio::test]
async fn custom_credential_field_names_are_used_for_local_auth() {
    let auth = HarbourAuth::new(LocalStrategy::new(
        InMemoryUserStore::new().with_user(
            "alice",
            Principal::new("local-1").with_name("Alice Local"),
            "password123",
        ),
        PlaintextPasswordVerifier,
    ))
    // Client sends "email" and "pass" instead of "username" / "password"
    .with_credential_fields("email", "pass");

    let app = Router::new()
        .route(
            "/login",
            post(local_handler).route_layer(middleware::from_fn_with_state(
                auth.clone(),
                require_auth,
            )),
        )
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"email":"alice","pass":"password123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"local:local-1");
}

#[tokio::test]
async fn default_field_names_still_work_without_override() {
    // Ensures the defaults haven't been broken by the configurable-field-names change.
    let response = protected_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login-local")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"alice","password":"password123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ── JWT strategy E2E tests ────────────────────────────────────────────────────────────────────────

const JWT_SECRET: &[u8] = b"e2e-jwt-test-secret";

#[tokio::test]
async fn jwt_strategy_valid_token_returns_200_and_principal() {
    let issuer = JwtIssuer::hs256(JWT_SECRET);
    let principal = Principal::new("jwt-user-1").with_name("JWT User");
    let token = issuer.issue(&principal).unwrap();

    let auth = HarbourAuth::new(JwtStrategy::hs256(JWT_SECRET));
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth))
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"jwt-user-1:JWT User");
}

#[tokio::test]
async fn jwt_strategy_invalid_token_returns_401() {
    let auth = HarbourAuth::new(JwtStrategy::hs256(JWT_SECRET));
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth))
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", "Bearer not.a.jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_strategy_token_with_roles_principal_has_roles() {
    let issuer = JwtIssuer::hs256(JWT_SECRET);
    let principal = Principal::new("jwt-admin-1")
        .with_name("Admin")
        .with_role("admin")
        .with_role("editor");
    let token = issuer.issue(&principal).unwrap();

    let auth = HarbourAuth::new(JwtStrategy::hs256(JWT_SECRET));

    async fn roles_handler(AuthPrincipal(p): AuthPrincipal) -> impl IntoResponse {
        format!(
            "{}:{}",
            p.id,
            p.roles
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    let app = Router::new()
        .route("/roles", get(roles_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth))
        .with_state(auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/roles")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.starts_with("jwt-admin-1:"));
    assert!(body_str.contains("admin"));
    assert!(body_str.contains("editor"));
}

// ── with_jwt_issuer convenience method ───────────────────────────────────────────────────────────

#[tokio::test]
async fn with_jwt_issuer_returns_access_token_in_body_after_login() {
    // Verifies the full login → JWT flow: local creds in, {"access_token": "..."} out.
    // The returned token must be a valid JWT verifiable by JwtStrategy.
    let secret = b"with-jwt-issuer-test-secret";

    let store = InMemoryUserStore::new().with_user(
        "bob",
        Principal::new("user-jwt-flow-1").with_name("Bob").with_role("member"),
        "pass123",
    );

    let login_auth =
        HarbourAuth::new(LocalStrategy::new(store, PlaintextPasswordVerifier))
            .with_jwt_issuer(JwtIssuer::hs256(secret));

    let app = Router::new()
        .route(
            "/login",
            post(local_handler).route_layer(middleware::from_fn_with_state(
                login_auth.clone(),
                require_auth,
            )),
        )
        .with_state(login_auth);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"bob","password":"pass123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("application/json"));

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token field must be present");

    // The issued token must be verifiable by JwtStrategy with the same secret.
    let api_auth = HarbourAuth::new(JwtStrategy::hs256(secret));
    let api_app = Router::new()
        .route("/me", get(protected_handler))
        .layer(middleware::from_fn_with_state(api_auth.clone(), require_auth))
        .with_state(api_auth);

    let api_response = api_app
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(api_response.status(), StatusCode::OK);
    let api_body = to_bytes(api_response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&api_body[..], b"user-jwt-flow-1:Bob");
}

#[tokio::test]
async fn with_jwt_issuer_bad_credentials_returns_401_without_token() {
    let secret = b"with-jwt-issuer-test-secret";

    let store = InMemoryUserStore::new().with_user(
        "carol",
        Principal::new("user-carol-1"),
        "correct",
    );

    let login_auth =
        HarbourAuth::new(LocalStrategy::new(store, PlaintextPasswordVerifier))
            .with_jwt_issuer(JwtIssuer::hs256(secret));

    let app = Router::new()
        .route(
            "/login",
            post(local_handler).route_layer(middleware::from_fn_with_state(
                login_auth.clone(),
                require_auth,
            )),
        )
        .with_state(login_auth);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"carol","password":"wrong"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}


// ── Refresh token support ─────────────────────────────────────────────────────────────────────────

const REFRESH_SECRET: &[u8] = b"refresh-e2e-test-secret";

#[tokio::test]
async fn with_jwt_issuer_refresh_enabled_returns_both_tokens_on_login() {
    let store = InMemoryUserStore::new().with_user(
        "diana",
        Principal::new("user-diana-1").with_name("Diana"),
        "secret123",
    );

    let login_auth = HarbourAuth::new(LocalStrategy::new(store, PlaintextPasswordVerifier))
        .with_jwt_issuer(JwtIssuer::hs256(REFRESH_SECRET).with_refresh_tokens());

    let app = Router::new()
        .route(
            "/login",
            post(local_handler).route_layer(middleware::from_fn_with_state(
                login_auth.clone(),
                require_auth,
            )),
        )
        .with_state(login_auth);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"diana","password":"secret123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("access_token").and_then(|v| v.as_str()).is_some());
    assert!(
        json.get("refresh_token").and_then(|v| v.as_str()).is_some(),
        "refresh_token must be present when .with_refresh_tokens() is set"
    );
}

#[tokio::test]
async fn refresh_endpoint_issues_new_token_pair_from_valid_refresh_token() {
    // Step 1 – obtain a refresh token from the login endpoint.
    let store = InMemoryUserStore::new().with_user(
        "evan",
        Principal::new("user-evan-1").with_name("Evan").with_role("member"),
        "pass456",
    );

    let login_auth = HarbourAuth::new(LocalStrategy::new(store, PlaintextPasswordVerifier))
        .with_jwt_issuer(JwtIssuer::hs256(REFRESH_SECRET).with_refresh_tokens());

    let login_app = Router::new()
        .route(
            "/login",
            post(local_handler).route_layer(middleware::from_fn_with_state(
                login_auth.clone(),
                require_auth,
            )),
        )
        .with_state(login_auth);

    let login_resp = login_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"evan","password":"pass456"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let login_body = to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&login_body).unwrap();
    let refresh_token = login_json["refresh_token"].as_str().unwrap().to_string();

    // Step 2 – use the refresh token to obtain a new token pair.
    let refresh_auth = HarbourAuth::new(JwtRefreshStrategy::hs256(REFRESH_SECRET))
        .with_jwt_issuer(JwtIssuer::hs256(REFRESH_SECRET).with_refresh_tokens());

    let refresh_app = Router::new()
        .route(
            "/token/refresh",
            post(local_handler).route_layer(middleware::from_fn_with_state(
                refresh_auth.clone(),
                require_auth,
            )),
        )
        .with_state(refresh_auth);

    let body_payload = serde_json::json!({ "refresh_token": refresh_token }).to_string();
    let refresh_resp = refresh_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token/refresh")
                .header("content-type", "application/json")
                .body(Body::from(body_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(refresh_resp.status(), StatusCode::OK);
    let refresh_body = to_bytes(refresh_resp.into_body(), usize::MAX).await.unwrap();
    let refresh_json: serde_json::Value = serde_json::from_slice(&refresh_body).unwrap();

    let new_access = refresh_json["access_token"].as_str().expect("new access_token");
    assert!(refresh_json.get("refresh_token").and_then(|v| v.as_str()).is_some());

    // Step 3 – the new access token must be accepted by the protected API.
    let api_auth = HarbourAuth::new(JwtStrategy::hs256(REFRESH_SECRET));
    let api_app = Router::new()
        .route("/me", get(protected_handler))
        .layer(middleware::from_fn_with_state(api_auth.clone(), require_auth))
        .with_state(api_auth);

    let api_resp = api_app
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("authorization", format!("Bearer {new_access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(api_resp.status(), StatusCode::OK);
    let api_body = to_bytes(api_resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&api_body[..], b"user-evan-1:Evan");
}

#[tokio::test]
async fn refresh_endpoint_rejects_access_token() {
    let issuer = JwtIssuer::hs256(REFRESH_SECRET);
    let access_token = issuer
        .issue(&Principal::new("user-x"))
        .unwrap();

    let refresh_auth = HarbourAuth::new(JwtRefreshStrategy::hs256(REFRESH_SECRET))
        .with_jwt_issuer(JwtIssuer::hs256(REFRESH_SECRET).with_refresh_tokens());

    let app = Router::new()
        .route(
            "/token/refresh",
            post(local_handler).route_layer(middleware::from_fn_with_state(
                refresh_auth.clone(),
                require_auth,
            )),
        )
        .with_state(refresh_auth);

    let body_payload = serde_json::json!({ "refresh_token": access_token }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token/refresh")
                .header("content-type", "application/json")
                .body(Body::from(body_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn access_token_not_accepted_on_bearer_protected_route_when_refresh_token_is_used() {
    // A refresh token must NOT be accepted by JwtStrategy on a regular API route.
    let issuer = JwtIssuer::hs256(REFRESH_SECRET).with_refresh_tokens();
    let refresh_token = issuer.issue_refresh(&Principal::new("user-y")).unwrap();

    let api_auth = HarbourAuth::new(JwtStrategy::hs256(REFRESH_SECRET));
    let app = Router::new()
        .route("/me", get(protected_handler))
        .layer(middleware::from_fn_with_state(api_auth.clone(), require_auth))
        .with_state(api_auth);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("authorization", format!("Bearer {refresh_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
