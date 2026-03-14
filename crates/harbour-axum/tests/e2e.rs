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
use harbour_strategy_local::{InMemoryUserStore, LocalStrategy, PlaintextPasswordVerifier};
use tower::ServiceExt;

/// Application-defined strategy enum — demonstrates the enum preference over bare strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppStrategy {
    User,
    Admin,
    Local,
}

impl StrategyName for AppStrategy {
    fn strategy_name(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Local => "local",
        }
    }
}

fn auth_config() -> HarbourAuth {
    HarbourAuth::new(
        AppStrategy::User,
        StaticBearerStrategy::new(
            "top-secret-token",
            Principal::new("user-123").with_name("Demo User"),
        ),
    )
    .with_strategy(
        AppStrategy::Admin,
        StaticBearerStrategy::new(
            "admin-token",
            Principal::new("admin-999").with_name("Admin User"),
        ),
    )
    .with_strategy(
        AppStrategy::Local,
        LocalStrategy::new(
            InMemoryUserStore::new().with_user(
                "alice",
                Principal::new("local-1").with_name("Alice Local"),
                "password123",
            ),
            PlaintextPasswordVerifier,
        ),
    )
}

fn protected_app() -> Router {
    let auth = auth_config();

    let protected = Router::new()
        .route("/protected", get(protected_handler))
        .route("/also-protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(auth.clone(), require_auth));

    // Use `with_active_strategy` + `require_auth` instead of a verbose closure
    // — addresses shortcoming 1 (strategy selection boilerplate).
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
    let auth = HarbourAuth::new(
        AppStrategy::Local,
        LocalStrategy::new(
            InMemoryUserStore::new().with_user(
                "alice",
                Principal::new("local-1").with_name("Alice Local"),
                "password123",
            ),
            PlaintextPasswordVerifier,
        ),
    )
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

