use async_trait::async_trait;
use axum::{
    body::to_bytes,
    extract::{FromRequestParts, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use harbour_core::{AuthContext, Authenticator, Principal, StrategyName, Strategy};
use std::{convert::Infallible, sync::Arc};

/// Maximum body size read by the auth middleware (64 KB).
/// Credential payloads are tiny; this prevents memory exhaustion from oversized requests.
const MAX_BODY_BYTES: usize = 64 * 1024;

type UnauthorizedResponder = Arc<dyn Fn() -> Response + Send + Sync>;

/// Post-authentication hook: receives the authenticated [`Principal`] and the handler's
/// [`Response`], and may transform the response (e.g. attach a JWT header or cookie).
type OnAuthenticatedHook = Arc<dyn Fn(&Principal, Response) -> Response + Send + Sync>;

/// Credential field names used when parsing a JSON request body.
///
/// Defaults to `username` / `password`, matching PassportJS Local Strategy conventions.
/// Override via [`HarbourAuth::with_credential_fields`].
#[derive(Debug, Clone)]
struct LocalCredentialConfig {
    username_field: String,
    password_field: String,
}

impl Default for LocalCredentialConfig {
    fn default() -> Self {
        Self {
            username_field: "username".to_string(),
            password_field: "password".to_string(),
        }
    }
}

pub struct HarbourAuth {
    authenticator: Arc<Authenticator>,
    default_strategy: String,
    unauthorized_responder: UnauthorizedResponder,
    on_authenticated: Option<OnAuthenticatedHook>,
    credential_fields: LocalCredentialConfig,
}

impl Clone for HarbourAuth {
    fn clone(&self) -> Self {
        Self {
            authenticator: Arc::clone(&self.authenticator),
            default_strategy: self.default_strategy.clone(),
            unauthorized_responder: Arc::clone(&self.unauthorized_responder),
            on_authenticated: self.on_authenticated.clone(),
            credential_fields: self.credential_fields.clone(),
        }
    }
}

impl HarbourAuth {
    /// Create a `HarbourAuth` using the strategy's own [`Strategy::strategy_name`] as the key.
    ///
    /// This is the idiomatic way to create a `HarbourAuth` — no separate name argument needed:
    ///
    /// ```rust,ignore
    /// // Login endpoint — strategy name is automatically "local":
    /// let login_auth = HarbourAuth::new(LocalStrategy::new(store, Argon2PasswordVerifier))
    ///     .with_jwt_issuer(JwtIssuer::hs256(secret));
    ///
    /// // Protected routes — strategy name is automatically "jwt":
    /// let api_auth = HarbourAuth::new(JwtStrategy::hs256(secret));
    /// ```
    pub fn new(strategy: impl Strategy + 'static) -> Self {
        let default_strategy = strategy.strategy_name().to_string();
        let authenticator = Authenticator::new().with_strategy(strategy);

        Self {
            authenticator: Arc::new(authenticator),
            default_strategy,
            unauthorized_responder: Arc::new(|| StatusCode::UNAUTHORIZED.into_response()),
            on_authenticated: None,
            credential_fields: LocalCredentialConfig::default(),
        }
    }

    /// Register an additional strategy using its own [`Strategy::strategy_name`].
    pub fn with_strategy(mut self, strategy: impl Strategy + 'static) -> Self {
        let name = strategy.strategy_name().to_string();
        Arc::make_mut(&mut self.authenticator)
            .register_strategy(name.as_str(), strategy);
        self
    }

    /// Register an additional strategy under an explicit custom name.
    ///
    /// Use this when you need to register multiple instances of the same strategy type under
    /// different names (e.g. two `JwtStrategy` instances with different secrets):
    ///
    /// ```rust,ignore
    /// let auth = HarbourAuth::new(LocalStrategy::new(store, verifier))
    ///     .with_strategy_named("jwt-internal", JwtStrategy::hs256(internal_secret))
    ///     .with_strategy_named("jwt-external", JwtStrategy::hs256(external_secret));
    /// ```
    pub fn with_strategy_named(
        mut self,
        strategy_name: impl StrategyName,
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

    /// Return a clone of this [`HarbourAuth`] with `strategy` set as the active (default) strategy.
    ///
    /// Use this with [`require_auth`] to select a per-route strategy without a verbose closure:
    ///
    /// ```rust,ignore
    /// post(handler).route_layer(middleware::from_fn_with_state(
    ///     auth.clone().with_active_strategy(MyStrategy::Admin),
    ///     require_auth,
    /// ))
    /// ```
    pub fn with_active_strategy(mut self, strategy: impl StrategyName) -> Self {
        self.default_strategy = strategy.strategy_name().to_string();
        self
    }

    /// Register a callback that is invoked after every successful authentication.
    ///
    /// The hook receives the authenticated [`Principal`] and the downstream handler's [`Response`]
    /// and may return a (possibly modified) response — for example, to attach a JWT or cookie:
    ///
    /// ```rust,ignore
    /// auth.with_on_authenticated(|principal, mut response| {
    ///     let token = issue_jwt(principal.id.as_str());
    ///     response.headers_mut().insert(
    ///         "x-auth-token",
    ///         token.parse().unwrap(),
    ///     );
    ///     response
    /// })
    /// ```
    pub fn with_on_authenticated<F>(mut self, hook: F) -> Self
    where
        F: Fn(&Principal, Response) -> Response + Send + Sync + 'static,
    {
        self.on_authenticated = Some(Arc::new(hook));
        self
    }

    /// Issue a signed JWT (`{"access_token": "..."}`) in the response body after every
    /// successful authentication.
    ///
    /// This is the recommended way to wire up a login endpoint: the [`JwtIssuer`] is stored
    /// inside `HarbourAuth` and invoked automatically — no manual `on_authenticated` hook needed.
    ///
    /// Enable the `jwt` feature on `harbour-axum` (on by default) to use this method.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Login route: verify credentials, respond with {"access_token": "..."}
    /// let login_auth = HarbourAuth::new("local", LocalStrategy::new(store, Argon2PasswordVerifier))
    ///     .with_jwt_issuer(JwtIssuer::hs256(secret));
    ///
    /// // Protected routes: verify the JWT on every request
    /// let api_auth = HarbourAuth::new("jwt", JwtStrategy::hs256(secret));
    /// ```
    #[cfg(feature = "jwt")]
    pub fn with_jwt_issuer(self, issuer: harbour_strategy_jwt::JwtIssuer) -> Self {
        let issuer = Arc::new(issuer);
        self.with_on_authenticated(move |principal, _response| {
            match issuer.issue(principal) {
                Ok(token) => {
                    let body = serde_json::json!({"access_token": token}).to_string();
                    // Response::builder() only fails for invalid header values. With a
                    // hardcoded status and "application/json" content-type that is impossible
                    // in practice, so the fallback to 500 is a belt-and-suspenders guard.
                    axum::response::Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        })
    }

    /// Override the JSON body field names used to extract credentials.
    ///
    /// Defaults to `username` / `password` (PassportJS Local Strategy convention).
    /// Use this when your clients send different field names, e.g. `email` / `pass`.
    pub fn with_credential_fields(
        mut self,
        username_field: impl Into<String>,
        password_field: impl Into<String>,
    ) -> Self {
        self.credential_fields = LocalCredentialConfig {
            username_field: username_field.into(),
            password_field: password_field.into(),
        };
        self
    }

    pub async fn middleware(&self, req: axum::extract::Request, next: Next) -> Response {
        self.middleware_with_strategy(req, next, None::<&str>).await
    }

    pub async fn middleware_with_strategy(
        &self,
        req: axum::extract::Request,
        next: Next,
        strategy_name: Option<impl StrategyName>,
    ) -> Response {
        let (mut parts, body) = req.into_parts();

        // Only buffer the body when the request declares a JSON content-type.
        // Bearer-only routes carry no body, so this avoids the allocation on the hot path.
        // Strips charset/boundary parameters before comparing (e.g. "application/json; charset=utf-8").
        let is_json = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
            .unwrap_or(false);

        let (context, body) = if is_json {
            let bytes = match to_bytes(body, MAX_BODY_BYTES).await {
                Ok(b) => b,
                Err(_) => return (self.unauthorized_responder)(),
            };
            let ctx = context_from_request(
                &parts.headers,
                &bytes,
                &self.credential_fields.username_field,
                &self.credential_fields.password_field,
            );
            (ctx, axum::body::Body::from(bytes))
        } else {
            (context_from_headers(&parts.headers), body)
        };

        let name = strategy_name
            .as_ref()
            .map(|s| s.strategy_name().to_string())
            .unwrap_or_else(|| self.default_strategy.clone());

        match self.authenticator.authenticate_with(name.as_str(), &context).await {
            Ok(principal) => {
                parts.extensions.insert(principal.clone());
                let req =
                    axum::extract::Request::from_parts(parts, body);
                let mut response = next.run(req).await;
                if let Some(hook) = &self.on_authenticated {
                    response = hook(&principal, response);
                }
                response
            }
            Err(_) => (self.unauthorized_responder)(),
        }
    }
}

/// Build an [`AuthContext`] from request headers only (no body).
///
/// - `Authorization: Bearer <token>` → `bearer_token`
pub fn context_from_headers(headers: &HeaderMap) -> AuthContext {
    let mut context = AuthContext::new();

    if let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        context = context.with_field("bearer_token", token);
    }

    context
}

/// Build an [`AuthContext`] from request headers and a buffered JSON body.
///
/// - `Authorization: Bearer <token>` → `bearer_token`
/// - JSON body fields `username_field` and `password_field` → `local.identifier` / `local.password`
///   (aligns with the PassportJS Local Strategy field naming convention)
pub fn context_from_request(
    headers: &HeaderMap,
    body: &[u8],
    username_field: &str,
    password_field: &str,
) -> AuthContext {
    let mut context = context_from_headers(headers);

    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(username) = json.get(username_field).and_then(|v| v.as_str()) {
            context = context.with_field("local.identifier", username);
        }
        if let Some(password) = json.get(password_field).and_then(|v| v.as_str()) {
            context = context.with_field("local.password", password);
        }
        // If the body is not JSON, or the fields are missing/wrong type, the
        // local.identifier / local.password keys are simply absent from the context.
        // LocalStrategy will then return AuthError::MissingCredentials → 401, which
        // is the correct client-visible outcome.
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

