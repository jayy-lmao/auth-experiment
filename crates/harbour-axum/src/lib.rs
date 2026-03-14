use async_trait::async_trait;
use axum::{
    extract::{FromRequestParts, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use harbour_core::{AuthContext, Authenticator, Principal, Strategy};
use std::{convert::Infallible, sync::Arc};

type UnauthorizedResponder = Arc<dyn Fn() -> Response + Send + Sync>;

pub struct HarbourAuth {
    authenticator: Arc<Authenticator>,
    default_strategy: String,
    unauthorized_responder: UnauthorizedResponder,
}

impl Clone for HarbourAuth {
    fn clone(&self) -> Self {
        Self {
            authenticator: Arc::clone(&self.authenticator),
            default_strategy: self.default_strategy.clone(),
            unauthorized_responder: Arc::clone(&self.unauthorized_responder),
        }
    }
}

impl HarbourAuth {
    pub fn new(default_strategy: impl Into<String>, strategy: impl Strategy + 'static) -> Self {
        let default_strategy = default_strategy.into();
        let authenticator = Authenticator::new().with_strategy(default_strategy.clone(), strategy);

        Self {
            authenticator: Arc::new(authenticator),
            default_strategy,
            unauthorized_responder: Arc::new(|| StatusCode::UNAUTHORIZED.into_response()),
        }
    }

    pub fn with_strategy(
        mut self,
        strategy_name: impl Into<String>,
        strategy: impl Strategy + 'static,
    ) -> Self {
        Arc::make_mut(&mut self.authenticator).register_strategy(strategy_name, strategy);
        self
    }

    /// Configure a custom 401 response payload/shape for failed authentication.
    pub fn with_unauthorized_response<F>(mut self, responder: F) -> Self
    where
        F: Fn() -> Response + Send + Sync + 'static,
    {
        self.unauthorized_responder = Arc::new(responder);
        self
    }

    pub async fn middleware(&self, req: axum::extract::Request, next: Next) -> Response {
        self.middleware_with_strategy(req, next, None).await
    }

    pub async fn middleware_with_strategy(
        &self,
        mut req: axum::extract::Request,
        next: Next,
        strategy_name: Option<&str>,
    ) -> Response {
        let context = context_from_headers(req.headers());
        let strategy_name = strategy_name.unwrap_or(self.default_strategy.as_str());

        match self
            .authenticator
            .authenticate_with(strategy_name, &context)
            .await
        {
            Ok(principal) => {
                req.extensions_mut().insert(principal);
                next.run(req).await
            }
            Err(_) => (self.unauthorized_responder)(),
        }
    }
}

pub fn context_from_headers(headers: &HeaderMap) -> AuthContext {
    let mut context = AuthContext::new();

    if let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        context = context.with_field("bearer_token", token);
    }

    if let Some(identifier) = headers
        .get("x-auth-identifier")
        .and_then(|v| v.to_str().ok())
    {
        context = context.with_field("local.identifier", identifier);
    }

    if let Some(password) = headers.get("x-auth-password").and_then(|v| v.to_str().ok()) {
        context = context.with_field("local.password", password);
    }

    context
}

#[derive(Debug, Clone)]
pub struct AuthPrincipal(pub Principal);

#[async_trait]
impl<S> FromRequestParts<S> for AuthPrincipal
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let principal = parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?;

        Ok(Self(principal))
    }
}

/// Optional principal extraction for handlers that support anonymous users.
#[derive(Debug, Clone)]
pub struct MaybeAuthPrincipal(pub Option<Principal>);

#[async_trait]
impl<S> FromRequestParts<S> for MaybeAuthPrincipal
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<Principal>().cloned()))
    }
}

pub async fn require_auth(
    State(auth): State<HarbourAuth>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    auth.middleware(req, next).await
}
