use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
    Router,
};
use harbour_axum::{require_auth, AuthPrincipal, HarbourAuth, MaybeAuthPrincipal};
use harbour_core::{Principal, StaticBearerStrategy};
use harbour_strategy_local::{InMemoryUserStore, LocalStrategy, PlaintextPasswordVerifier};
use tower::ServiceExt;

fn auth_config() -> HarbourAuth {
    HarbourAuth::new(
        "user",
        StaticBearerStrategy::new(
            "top-secret-token",
            Principal::new("user-123").with_name("Demo User"),
        ),
    )
    .with_strategy(
        "admin",
        StaticBearerStrategy::new(
            "admin-token",
            Principal::new("admin-999").with_name("Admin User"),
        ),
    )
    .with_strategy(
        "local",
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

    let admin = Router::new().route(
        "/admin",
        get(admin_handler).route_layer(middleware::from_fn_with_state(
            auth.clone(),
            |State(auth): State<HarbourAuth>, req, next| async move {
                auth.middleware_with_strategy(req, next, Some("admin"))
                    .await
            },
        )),
    );

    let local = Router::new().route(
        "/login-local",
        get(local_handler).route_layer(middleware::from_fn_with_state(
            auth.clone(),
            |State(auth): State<HarbourAuth>, req, next| async move {
                auth.middleware_with_strategy(req, next, Some("local"))
                    .await
            },
        )),
    );

    let unknown_strategy = Router::new().route(
        "/unknown-strategy",
        get(protected_handler).route_layer(middleware::from_fn_with_state(
            auth.clone(),
            |State(auth): State<HarbourAuth>, req, next| async move {
                auth.middleware_with_strategy(req, next, Some("does-not-exist"))
                    .await
            },
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
async fn local_strategy_authenticates_from_headers() {
    let response = protected_app()
        .oneshot(
            Request::builder()
                .uri("/login-local")
                .header("x-auth-identifier", "alice")
                .header("x-auth-password", "password123")
                .body(Body::empty())
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
                .uri("/login-local")
                .header("x-auth-identifier", "alice")
                .header("x-auth-password", "wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
