use async_trait::async_trait;
use harbour_core::{AuthContext, AuthError, Principal, Strategy};
use harbour_strategy_jwt::{JwtError, JwtIssuer, JwtStrategy};

/// Default cookie name used by [`SessionCookieIssuer`] and [`SessionCookieStrategy`].
///
/// Mirrors the `.AspNetCore.Cookies` default from .NET Identity Framework.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = ".harbour.session";

/// Controls the `SameSite` attribute on session cookies.
///
/// See [MDN SameSite documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
/// for a description of each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// The browser only sends the cookie with same-site requests.
    Strict,
    /// The cookie is sent with same-site requests and with cross-site top-level navigations.
    ///
    /// This is the default — it provides good CSRF protection while allowing normal navigation.
    Lax,
    /// The cookie is sent with both same-site and cross-site requests.
    ///
    /// Requires `Secure` to be set; use for third-party cookie scenarios.
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Lax => write!(f, "Lax"),
            Self::None => write!(f, "None"),
        }
    }
}

/// Issues signed session cookies on successful authentication.
///
/// The cookie value is a signed JWT, providing tamper-proof session data without
/// server-side session storage — analogous to .NET Identity Framework's
/// [cookie authentication handler](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie).
///
/// ## Cookie attributes
///
/// - `HttpOnly` — always set; prevents JavaScript access.
/// - `Path=/` — always set; cookie is valid for the entire site.
/// - `SameSite` — configurable (default [`SameSite::Lax`]); provides CSRF protection.
/// - `Secure` — configurable (default `false`); set `true` in production (HTTPS only).
///
/// ## Example
///
/// ```rust,ignore
/// use harbour_strategy_session::SessionCookieIssuer;
///
/// let secret = b"my-session-secret";
///
/// // Login endpoint: issues a session cookie on success.
/// let login_auth = HarbourAuth::new(LocalStrategy::new(store, Argon2PasswordVerifier))
///     .with_session_cookie_issuer(SessionCookieIssuer::hs256(secret));
/// ```
pub struct SessionCookieIssuer {
    jwt_issuer: JwtIssuer,
    cookie_name: String,
    secure: bool,
    same_site: SameSite,
}

impl SessionCookieIssuer {
    /// Create a session cookie issuer that signs cookies with HMAC-SHA-256.
    ///
    /// Cookie lifetime defaults to 1 hour. Override with [`with_expiry`][Self::with_expiry].
    pub fn hs256(secret: &[u8]) -> Self {
        Self {
            jwt_issuer: JwtIssuer::hs256(secret),
            cookie_name: DEFAULT_SESSION_COOKIE_NAME.to_string(),
            secure: false,
            same_site: SameSite::Lax,
        }
    }

    /// Create a session cookie issuer that signs cookies with RSA-SHA-256.
    ///
    /// `private_key_pem` should be a PEM-encoded RSA private key.
    pub fn rs256(private_key_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(Self {
            jwt_issuer: JwtIssuer::rs256(private_key_pem)?,
            cookie_name: DEFAULT_SESSION_COOKIE_NAME.to_string(),
            secure: false,
            same_site: SameSite::Lax,
        })
    }

    /// Override the session cookie name.
    ///
    /// Default: `.harbour.session`
    ///
    /// Must match the name used by the corresponding [`SessionCookieStrategy`].
    pub fn with_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = name.into();
        self
    }

    /// Set the `Secure` attribute on the cookie.
    ///
    /// Enable this in production when serving over HTTPS so the cookie is never
    /// sent over plain HTTP.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Override the `SameSite` attribute (default: [`SameSite::Lax`]).
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Override the session lifetime in seconds.
    ///
    /// Default: 3600 seconds (1 hour).
    pub fn with_expiry(mut self, expiry_secs: u64) -> Self {
        self.jwt_issuer = self.jwt_issuer.with_expiry(expiry_secs);
        self
    }

    /// Returns the cookie name used by this issuer.
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// Build a `Set-Cookie` header value for the given [`Principal`].
    ///
    /// The value encodes the principal as a signed JWT and attaches the configured
    /// cookie attributes (`HttpOnly`, `Path=/`, `SameSite`, and optionally `Secure`).
    pub fn issue_set_cookie_header(&self, principal: &Principal) -> Result<String, JwtError> {
        let token = self.jwt_issuer.issue(principal)?;

        let mut cookie = format!(
            "{}={}; HttpOnly; Path=/; SameSite={}",
            self.cookie_name, token, self.same_site
        );

        if self.secure {
            cookie.push_str("; Secure");
        }

        Ok(cookie)
    }
}

/// A [`Strategy`] that authenticates requests by verifying a signed session cookie.
///
/// The session cookie value is a JWT issued by [`SessionCookieIssuer`].  The Axum adapter
/// extracts the named cookie from the `Cookie` request header and stores it in the
/// `session_token` context key, which this strategy then validates.
///
/// ## Supported algorithms
///
/// | Constructor | Algorithm |
/// |---|---|
/// | [`SessionCookieStrategy::hs256`] | HMAC-SHA-256 (shared secret) |
/// | [`SessionCookieStrategy::rs256`] | RSA-SHA-256 (public key) |
///
/// ## Example
///
/// ```rust,ignore
/// use harbour_strategy_session::{SessionCookieIssuer, SessionCookieStrategy};
///
/// let secret = b"my-session-secret";
///
/// // Login endpoint: issues a session cookie on success.
/// let login_auth = HarbourAuth::new(LocalStrategy::new(store, Argon2PasswordVerifier))
///     .with_session_cookie_issuer(SessionCookieIssuer::hs256(secret));
///
/// // Protected routes: validates the session cookie on every request.
/// let api_auth = HarbourAuth::new(SessionCookieStrategy::hs256(secret));
/// ```
pub struct SessionCookieStrategy {
    inner: JwtStrategy,
    cookie_name: String,
}

impl SessionCookieStrategy {
    /// Create a session cookie strategy that verifies cookies signed with HMAC-SHA-256.
    pub fn hs256(secret: &[u8]) -> Self {
        Self {
            inner: JwtStrategy::hs256(secret),
            cookie_name: DEFAULT_SESSION_COOKIE_NAME.to_string(),
        }
    }

    /// Create a session cookie strategy that verifies cookies signed with RSA-SHA-256.
    ///
    /// `public_key_pem` should be a PEM-encoded RSA public key.
    pub fn rs256(public_key_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(Self {
            inner: JwtStrategy::rs256(public_key_pem)?,
            cookie_name: DEFAULT_SESSION_COOKIE_NAME.to_string(),
        })
    }

    /// Override the session cookie name.
    ///
    /// Must match the name used by the corresponding [`SessionCookieIssuer`].
    pub fn with_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = name.into();
        self
    }

    /// Returns the cookie name this strategy reads.
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }
}

#[async_trait]
impl Strategy for SessionCookieStrategy {
    fn strategy_name(&self) -> &str {
        "session"
    }

    async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError> {
        let token = context
            .get("session_token")
            .ok_or(AuthError::MissingCredentials)?;

        // The session token is a JWT — delegate to JwtStrategy for validation.
        // We proxy the token through the bearer_token context key since that is
        // what JwtStrategy reads.
        let proxy_context = AuthContext::new().with_field("bearer_token", token);
        self.inner.authenticate(&proxy_context).await
    }
}

/// Default cookie name for the access token issued by [`JwtCookieIssuer`].
pub const DEFAULT_ACCESS_TOKEN_COOKIE_NAME: &str = "access_token";

/// Default cookie name for the refresh token issued by [`JwtCookieIssuer`].
pub const DEFAULT_REFRESH_TOKEN_COOKIE_NAME: &str = "refresh_token";

/// Issues JWT access (and optionally refresh) tokens as `HttpOnly` cookies.
///
/// Similar to [`SessionCookieIssuer`] but issues the standard JWT access/refresh token
/// pair via separate cookies rather than a single opaque session cookie. This is useful
/// when you want all three of: XSS protection (HttpOnly), stateless JWTs, and the
/// access + refresh token rotation pattern.
///
/// The middleware automatically injects the cookies back into the `AuthContext` so that
/// [`harbour_strategy_jwt::JwtStrategy`] and [`harbour_strategy_jwt::JwtRefreshStrategy`]
/// can verify them without any extra configuration.
///
/// Use with [`HarbourAuth::with_jwt_cookie_issuer`] in the Axum adapter, which wires
/// everything up automatically.
///
/// ## Cookie attributes
///
/// - `HttpOnly` — always set; prevents JavaScript access.
/// - `Path=/` — always set; cookie is valid for the entire site.
/// - `SameSite` — configurable (default [`SameSite::Lax`]); provides CSRF protection.
/// - `Secure` — configurable (default `false`); set `true` in production (HTTPS only).
///
/// ## Example
///
/// All examples in this library are `rust,ignore` because they span multiple crates
/// wired together via an Axum router.
///
/// ```rust,ignore
/// use harbour_strategy_session::JwtCookieIssuer;
/// use harbour_strategy_jwt::{JwtRefreshStrategy, JwtStrategy};
///
/// let secret = b"my-secret";
///
/// // Login endpoint: sets access_token (and refresh_token) cookies on success.
/// let login_auth = HarbourAuth::new(LocalStrategy::new(store, Argon2PasswordVerifier))
///     .with_jwt_cookie_issuer(JwtCookieIssuer::hs256(secret).with_refresh_tokens());
///
/// // Refresh endpoint: reads refresh_token cookie, issues new cookie pair.
/// let refresh_auth = HarbourAuth::new(JwtRefreshStrategy::hs256(secret))
///     .with_jwt_cookie_issuer(JwtCookieIssuer::hs256(secret).with_refresh_tokens());
///
/// // Protected routes: reads access_token cookie via JwtStrategy.
/// let api_auth = HarbourAuth::new(JwtStrategy::hs256(secret));
/// ```
pub struct JwtCookieIssuer {
    inner: JwtIssuer,
    access_cookie_name: String,
    refresh_cookie_name: String,
    secure: bool,
    same_site: SameSite,
}

impl JwtCookieIssuer {
    /// Create a JWT cookie issuer that signs tokens with HMAC-SHA-256.
    pub fn hs256(secret: &[u8]) -> Self {
        Self {
            inner: JwtIssuer::hs256(secret),
            access_cookie_name: DEFAULT_ACCESS_TOKEN_COOKIE_NAME.to_string(),
            refresh_cookie_name: DEFAULT_REFRESH_TOKEN_COOKIE_NAME.to_string(),
            secure: false,
            same_site: SameSite::Lax,
        }
    }

    /// Create a JWT cookie issuer that signs tokens with RSA-SHA-256.
    ///
    /// `private_key_pem` should be a PEM-encoded RSA private key.
    pub fn rs256(private_key_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(Self {
            inner: JwtIssuer::rs256(private_key_pem)?,
            access_cookie_name: DEFAULT_ACCESS_TOKEN_COOKIE_NAME.to_string(),
            refresh_cookie_name: DEFAULT_REFRESH_TOKEN_COOKIE_NAME.to_string(),
            secure: false,
            same_site: SameSite::Lax,
        })
    }

    /// Override the cookie name used for the access token (default: `access_token`).
    pub fn with_access_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.access_cookie_name = name.into();
        self
    }

    /// Override the cookie name used for the refresh token (default: `refresh_token`).
    pub fn with_refresh_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.refresh_cookie_name = name.into();
        self
    }

    /// Set the `Secure` attribute on issued cookies.
    ///
    /// Enable this in production when serving over HTTPS.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Override the `SameSite` attribute (default: [`SameSite::Lax`]).
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Override the access token lifetime in seconds (default: 3600 / 1 hour).
    pub fn with_expiry(mut self, expiry_secs: u64) -> Self {
        self.inner = self.inner.with_expiry(expiry_secs);
        self
    }

    /// Enable refresh token cookie issuance with the default 7-day lifetime.
    ///
    /// When enabled, [`HarbourAuth::with_jwt_cookie_issuer`] sets both an `access_token`
    /// and a `refresh_token` `Set-Cookie` header on every successful login.
    pub fn with_refresh_tokens(mut self) -> Self {
        self.inner = self.inner.with_refresh_tokens();
        self
    }

    /// Override the refresh token lifetime in seconds.
    ///
    /// Implicitly enables refresh tokens (same as calling [`with_refresh_tokens`] first).
    ///
    /// [`with_refresh_tokens`]: JwtCookieIssuer::with_refresh_tokens
    pub fn with_refresh_expiry(mut self, expiry_secs: u64) -> Self {
        self.inner = self.inner.with_refresh_expiry(expiry_secs);
        self
    }

    /// Returns `true` if refresh token cookie issuance is enabled on this issuer.
    pub fn has_refresh_tokens(&self) -> bool {
        self.inner.has_refresh_tokens()
    }

    /// Returns the access token cookie name.
    pub fn access_cookie_name(&self) -> &str {
        &self.access_cookie_name
    }

    /// Returns the refresh token cookie name.
    pub fn refresh_cookie_name(&self) -> &str {
        &self.refresh_cookie_name
    }

    fn build_cookie_header(&self, name: &str, value: &str) -> String {
        let mut cookie = format!(
            "{}={}; HttpOnly; Path=/; SameSite={}",
            name, value, self.same_site
        );
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie
    }

    /// Build a `Set-Cookie` header value for the access token.
    pub fn issue_access_cookie_header(&self, principal: &Principal) -> Result<String, JwtError> {
        let token = self.inner.issue(principal)?;
        Ok(self.build_cookie_header(&self.access_cookie_name, &token))
    }

    /// Build a `Set-Cookie` header value for the refresh token.
    ///
    /// Returns [`JwtError::RefreshNotEnabled`] if refresh tokens have not been configured.
    pub fn issue_refresh_cookie_header(&self, principal: &Principal) -> Result<String, JwtError> {
        let token = self.inner.issue_refresh(principal)?;
        Ok(self.build_cookie_header(&self.refresh_cookie_name, &token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbour_core::Authenticator;

    #[tokio::test]
    async fn session_strategy_authenticates_valid_cookie() {
        let secret = b"test-secret";
        let issuer = SessionCookieIssuer::hs256(secret);
        let strategy = SessionCookieStrategy::hs256(secret);

        let principal = Principal::new("user-1").with_name("Alice").with_role("admin");
        let cookie_header = issuer.issue_set_cookie_header(&principal).unwrap();

        // Extract the token from the Set-Cookie header value.
        let token = cookie_header
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;

        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new().with_field("session_token", token);
        let result = auth.authenticate(&context).await.unwrap();

        assert_eq!(result.id, "user-1");
        assert_eq!(result.name.as_deref(), Some("Alice"));
        assert!(result.has_role("admin"));
    }

    #[tokio::test]
    async fn session_strategy_rejects_missing_cookie() {
        let strategy = SessionCookieStrategy::hs256(b"test-secret");
        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new();

        let err = auth.authenticate(&context).await.unwrap_err();
        assert_eq!(err, AuthError::MissingCredentials);
    }

    #[tokio::test]
    async fn session_strategy_rejects_tampered_token() {
        let strategy = SessionCookieStrategy::hs256(b"test-secret");
        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new().with_field("session_token", "tampered.invalid.token");

        let err = auth.authenticate(&context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn session_strategy_rejects_token_signed_with_different_secret() {
        let issuer = SessionCookieIssuer::hs256(b"other-secret");
        let strategy = SessionCookieStrategy::hs256(b"my-secret");

        let principal = Principal::new("user-1");
        let cookie_header = issuer.issue_set_cookie_header(&principal).unwrap();
        let token = cookie_header
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;

        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new().with_field("session_token", token);

        let err = auth.authenticate(&context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[test]
    fn issuer_set_cookie_header_contains_required_attributes() {
        let issuer = SessionCookieIssuer::hs256(b"secret");
        let principal = Principal::new("user-1");
        let header = issuer.issue_set_cookie_header(&principal).unwrap();

        assert!(header.starts_with(".harbour.session="));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("SameSite=Lax"));
        assert!(!header.contains("Secure"), "Secure should not be set by default");
    }

    #[test]
    fn issuer_with_secure_adds_secure_attribute() {
        let issuer = SessionCookieIssuer::hs256(b"secret").with_secure(true);
        let principal = Principal::new("user-1");
        let header = issuer.issue_set_cookie_header(&principal).unwrap();

        assert!(header.contains("Secure"));
    }

    #[test]
    fn issuer_with_custom_cookie_name_uses_that_name() {
        let issuer = SessionCookieIssuer::hs256(b"secret").with_cookie_name("my.auth");
        let principal = Principal::new("user-1");
        let header = issuer.issue_set_cookie_header(&principal).unwrap();

        assert!(header.starts_with("my.auth="));
        assert_eq!(issuer.cookie_name(), "my.auth");
    }

    #[test]
    fn issuer_with_same_site_strict_sets_attribute() {
        let issuer = SessionCookieIssuer::hs256(b"secret").with_same_site(SameSite::Strict);
        let principal = Principal::new("user-1");
        let header = issuer.issue_set_cookie_header(&principal).unwrap();

        assert!(header.contains("SameSite=Strict"));
    }

    #[tokio::test]
    async fn custom_cookie_name_is_preserved_on_strategy() {
        let secret = b"secret";
        let issuer = SessionCookieIssuer::hs256(secret).with_cookie_name("my.auth");
        let strategy = SessionCookieStrategy::hs256(secret).with_cookie_name("my.auth");

        let principal = Principal::new("user-42");
        let cookie_header = issuer.issue_set_cookie_header(&principal).unwrap();
        let token = cookie_header
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;

        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new().with_field("session_token", token);
        let result = auth.authenticate(&context).await.unwrap();
        assert_eq!(result.id, "user-42");
    }

    #[test]
    fn strategy_name_and_default_cookie_name_are_correct() {
        let strategy = SessionCookieStrategy::hs256(b"secret");
        assert_eq!(strategy.strategy_name(), "session");
        assert_eq!(strategy.cookie_name(), DEFAULT_SESSION_COOKIE_NAME);
    }
}
