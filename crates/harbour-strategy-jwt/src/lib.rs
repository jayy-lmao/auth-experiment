use async_trait::async_trait;
use harbour_core::{AuthContext, AuthError, Principal, Strategy};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT claims used by [`JwtStrategy`] and [`JwtIssuer`].
///
/// Maps standard JWT claims to [`Principal`] fields:
/// - `sub` ↔ `Principal::id`
/// - `name` ↔ `Principal::name`
/// - `roles` ↔ `Principal::roles`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject — the principal's unique identifier.
    pub sub: String,
    /// Human-readable display name (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Roles assigned to the principal for RBAC checks.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Expiration time (seconds since UNIX epoch).
    pub exp: u64,
    /// Issued-at time (seconds since UNIX epoch).
    pub iat: u64,
    /// Token type: `"access"` or `"refresh"`.
    ///
    /// Absent on tokens issued before refresh support was added — treated as `"access"`.
    /// [`JwtStrategy`] rejects tokens with `token_type = "refresh"`.
    /// [`JwtRefreshStrategy`] requires `token_type = "refresh"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl From<JwtClaims> for Principal {
    fn from(claims: JwtClaims) -> Self {
        let mut p = Principal::new(claims.sub);
        if let Some(name) = claims.name {
            p = p.with_name(name);
        }
        for role in claims.roles {
            p = p.with_role(role);
        }
        p
    }
}

/// Error type for JWT operations.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("JWT encoding failed: {0}")]
    Encoding(#[from] jsonwebtoken::errors::Error),
    #[error("system clock is unavailable")]
    Clock,
    #[error("refresh tokens are not enabled on this issuer; call .with_refresh_tokens() first")]
    RefreshNotEnabled,
}

/// A [`Strategy`] that authenticates requests by verifying a JWT Bearer token.
///
/// The token must be present in the `Authorization: Bearer <token>` header;
/// the Axum adapter automatically extracts it into the `bearer_token` context key.
///
/// ## Supported algorithms
///
/// | Constructor | Algorithm |
/// |---|---|
/// | [`JwtStrategy::hs256`] | HMAC-SHA-256 (shared secret) |
/// | [`JwtStrategy::rs256`] | RSA-SHA-256 (public key) |
///
/// ## Example
///
/// ```rust,ignore
/// use harbour_strategy_jwt::{JwtIssuer, JwtStrategy};
/// use harbour_core::{Authenticator, Principal};
///
/// let secret = b"super-secret-key";
/// let issuer = JwtIssuer::hs256(secret);
/// let strategy = JwtStrategy::hs256(secret);
///
/// let token = issuer.issue(&Principal::new("user-1").with_role("admin")).unwrap();
/// // Use `token` as Bearer token in Authorization header.
/// ```
pub struct JwtStrategy {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtStrategy {
    /// Create a JWT strategy that verifies tokens signed with HMAC-SHA-256.
    pub fn hs256(secret: &[u8]) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation: Validation::new(jsonwebtoken::Algorithm::HS256),
        }
    }

    /// Create a JWT strategy that verifies tokens signed with RSA-SHA-256.
    ///
    /// `public_key_pem` should be a PEM-encoded RSA public key.
    pub fn rs256(public_key_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(Self {
            decoding_key: DecodingKey::from_rsa_pem(public_key_pem)
                .map_err(JwtError::Encoding)?,
            validation: Validation::new(jsonwebtoken::Algorithm::RS256),
        })
    }
}

#[async_trait]
impl Strategy for JwtStrategy {
    fn strategy_name(&self) -> &str {
        "jwt"
    }

    async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError> {
        let token = context
            .get("bearer_token")
            .ok_or(AuthError::MissingCredentials)?;

        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|_| AuthError::InvalidCredentials)?;

        // Reject refresh tokens — they must not be used as access tokens.
        if token_data.claims.token_type.as_deref() == Some("refresh") {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(token_data.claims.into())
    }
}

/// Default token lifetime used by [`JwtIssuer`] when no expiry is specified.
///
/// Override with [`JwtIssuer::with_expiry`] when a different lifetime is needed.
pub const DEFAULT_TOKEN_EXPIRY_SECS: u64 = 3600; // 1 hour

/// Default refresh token lifetime used by [`JwtIssuer`] when [`JwtIssuer::with_refresh_tokens`]
/// is called without a custom expiry.
///
/// Override with [`JwtIssuer::with_refresh_expiry`] when a different lifetime is needed.
pub const DEFAULT_REFRESH_EXPIRY_SECS: u64 = 7 * 24 * 3600; // 7 days

/// Issues signed JWTs that can be verified by [`JwtStrategy`].
///
/// Intended for use in login handlers — typically via [`HarbourAuth::with_jwt_issuer`] in the
/// Axum adapter, which wires everything up automatically.
///
/// ## Refresh tokens (opt-in)
///
/// Call [`JwtIssuer::with_refresh_tokens`] to enable refresh token issuance. When enabled,
/// [`HarbourAuth::with_jwt_issuer`] automatically includes a `refresh_token` field alongside
/// `access_token` in the login response body.
///
/// Use [`JwtRefreshStrategy`] on your refresh endpoint to validate refresh tokens and issue new ones.
///
/// ## Example
///
/// ```rust,ignore
/// use harbour_strategy_jwt::JwtIssuer;
/// use harbour_core::Principal;
///
/// // 1-hour access token, 7-day refresh token:
/// let issuer = JwtIssuer::hs256(b"super-secret-key").with_refresh_tokens();
///
/// // Override expiry when needed:
/// let issuer = JwtIssuer::hs256(b"super-secret-key")
///     .with_expiry(15 * 60)           // 15-minute access token
///     .with_refresh_expiry(30 * 24 * 3600); // 30-day refresh token
///
/// let access  = issuer.issue(&Principal::new("user-1")).unwrap();
/// let refresh = issuer.issue_refresh(&Principal::new("user-1")).unwrap();
/// ```
pub struct JwtIssuer {
    encoding_key: EncodingKey,
    header: Header,
    expiry_secs: u64,
    /// `Some(expiry_secs)` means refresh tokens are enabled.
    refresh_expiry_secs: Option<u64>,
}

impl JwtIssuer {
    /// Create a JWT issuer that signs tokens with HMAC-SHA-256.
    ///
    /// Tokens are valid for [`DEFAULT_TOKEN_EXPIRY_SECS`] (1 hour) by default.
    /// Call `.with_expiry(secs)` to override.
    pub fn hs256(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            header: Header::new(jsonwebtoken::Algorithm::HS256),
            expiry_secs: DEFAULT_TOKEN_EXPIRY_SECS,
            refresh_expiry_secs: None,
        }
    }

    /// Create a JWT issuer that signs tokens with RSA-SHA-256.
    ///
    /// `private_key_pem` should be a PEM-encoded RSA private key.
    /// Tokens are valid for [`DEFAULT_TOKEN_EXPIRY_SECS`] (1 hour) by default.
    /// Call `.with_expiry(secs)` to override.
    pub fn rs256(private_key_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(Self {
            encoding_key: EncodingKey::from_rsa_pem(private_key_pem)
                .map_err(JwtError::Encoding)?,
            header: Header::new(jsonwebtoken::Algorithm::RS256),
            expiry_secs: DEFAULT_TOKEN_EXPIRY_SECS,
            refresh_expiry_secs: None,
        })
    }

    /// Override the access token lifetime.
    ///
    /// ```rust,ignore
    /// // Access tokens valid for 15 minutes:
    /// let issuer = JwtIssuer::hs256(secret).with_expiry(15 * 60);
    /// ```
    pub fn with_expiry(mut self, expiry_secs: u64) -> Self {
        self.expiry_secs = expiry_secs;
        self
    }

    /// Enable refresh token issuance with the default lifetime ([`DEFAULT_REFRESH_EXPIRY_SECS`], 7 days).
    ///
    /// When enabled, [`HarbourAuth::with_jwt_issuer`] automatically includes a `refresh_token`
    /// field in the login response body alongside `access_token`.
    ///
    /// Use [`JwtRefreshStrategy`] on your `/token/refresh` endpoint to validate refresh tokens
    /// and issue new ones:
    ///
    /// ```rust,ignore
    /// let secret = b"super-secret";
    ///
    /// // Login: issues {"access_token": "...", "refresh_token": "..."}
    /// let login_auth = HarbourAuth::new(LocalStrategy::new(store, Argon2PasswordVerifier))
    ///     .with_jwt_issuer(JwtIssuer::hs256(secret).with_refresh_tokens());
    ///
    /// // Refresh: validates refresh token, issues new token pair
    /// let refresh_auth = HarbourAuth::new(JwtRefreshStrategy::hs256(secret))
    ///     .with_jwt_issuer(JwtIssuer::hs256(secret).with_refresh_tokens());
    /// ```
    pub fn with_refresh_tokens(mut self) -> Self {
        if self.refresh_expiry_secs.is_none() {
            self.refresh_expiry_secs = Some(DEFAULT_REFRESH_EXPIRY_SECS);
        }
        self
    }

    /// Override the refresh token lifetime.
    ///
    /// Implicitly enables refresh tokens (same effect as calling [`JwtIssuer::with_refresh_tokens`] first).
    ///
    /// ```rust,ignore
    /// // 30-day refresh tokens:
    /// let issuer = JwtIssuer::hs256(secret).with_refresh_expiry(30 * 24 * 3600);
    /// ```
    pub fn with_refresh_expiry(mut self, expiry_secs: u64) -> Self {
        self.refresh_expiry_secs = Some(expiry_secs);
        self
    }

    /// Returns `true` if refresh token issuance is enabled on this issuer.
    pub fn has_refresh_tokens(&self) -> bool {
        self.refresh_expiry_secs.is_some()
    }

    /// Issue a signed access JWT for the given [`Principal`].
    ///
    /// The token encodes the principal's `id`, `name`, and `roles` as standard
    /// JWT claims (`sub`, `name`, `roles`), plus `iat`, `exp`, and `token_type = "access"`.
    pub fn issue(&self, principal: &Principal) -> Result<String, JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::Clock)?
            .as_secs();

        let claims = JwtClaims {
            sub: principal.id.clone(),
            name: principal.name.clone(),
            roles: principal.roles.clone(),
            iat: now,
            exp: now + self.expiry_secs,
            token_type: Some("access".to_string()),
        };

        encode(&self.header, &claims, &self.encoding_key).map_err(JwtError::Encoding)
    }

    /// Issue a signed refresh JWT for the given [`Principal`].
    ///
    /// The refresh token has `token_type = "refresh"` and a longer expiry
    /// (configured via [`with_refresh_tokens`] / [`with_refresh_expiry`]).
    ///
    /// Returns [`JwtError::RefreshNotEnabled`] if refresh tokens have not been configured.
    ///
    /// [`with_refresh_tokens`]: JwtIssuer::with_refresh_tokens
    /// [`with_refresh_expiry`]: JwtIssuer::with_refresh_expiry
    pub fn issue_refresh(&self, principal: &Principal) -> Result<String, JwtError> {
        let expiry_secs = self.refresh_expiry_secs.ok_or(JwtError::RefreshNotEnabled)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::Clock)?
            .as_secs();

        let claims = JwtClaims {
            sub: principal.id.clone(),
            name: principal.name.clone(),
            roles: principal.roles.clone(),
            iat: now,
            exp: now + expiry_secs,
            token_type: Some("refresh".to_string()),
        };

        encode(&self.header, &claims, &self.encoding_key).map_err(JwtError::Encoding)
    }
}

/// A [`Strategy`] that authenticates a refresh request by verifying a JWT refresh token.
///
/// Expects the refresh token in the `refresh_token` context key — populated by the Axum adapter
/// when the request body contains `{"refresh_token": "..."}`.
///
/// Returns [`AuthError::InvalidCredentials`] if the token is missing, expired, tampered with,
/// or is an access token (`token_type != "refresh"`).
///
/// ## Supported algorithms
///
/// | Constructor | Algorithm |
/// |---|---|
/// | [`JwtRefreshStrategy::hs256`] | HMAC-SHA-256 (shared secret) |
/// | [`JwtRefreshStrategy::rs256`] | RSA-SHA-256 (public key) |
///
/// ## Example
///
/// ```rust,ignore
/// use harbour_strategy_jwt::{JwtIssuer, JwtRefreshStrategy};
///
/// let secret = b"super-secret-key";
///
/// // Refresh endpoint: validate the refresh token and issue a new token pair.
/// let refresh_auth = HarbourAuth::new(JwtRefreshStrategy::hs256(secret))
///     .with_jwt_issuer(JwtIssuer::hs256(secret).with_refresh_tokens());
/// ```
pub struct JwtRefreshStrategy {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtRefreshStrategy {
    /// Create a refresh strategy that validates tokens signed with HMAC-SHA-256.
    pub fn hs256(secret: &[u8]) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation: Validation::new(jsonwebtoken::Algorithm::HS256),
        }
    }

    /// Create a refresh strategy that validates tokens signed with RSA-SHA-256.
    ///
    /// `public_key_pem` should be a PEM-encoded RSA public key.
    pub fn rs256(public_key_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(Self {
            decoding_key: DecodingKey::from_rsa_pem(public_key_pem)
                .map_err(JwtError::Encoding)?,
            validation: Validation::new(jsonwebtoken::Algorithm::RS256),
        })
    }
}

#[async_trait]
impl Strategy for JwtRefreshStrategy {
    fn strategy_name(&self) -> &str {
        "jwt-refresh"
    }

    async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError> {
        let token = context
            .get("refresh_token")
            .ok_or(AuthError::MissingCredentials)?;

        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|_| AuthError::InvalidCredentials)?;

        // Must be a refresh token — reject access tokens used on the refresh endpoint.
        if token_data.claims.token_type.as_deref() != Some("refresh") {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(token_data.claims.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbour_core::Authenticator;

    const SECRET: &[u8] = b"test-secret-key-for-harbour";

    fn make_issuer() -> JwtIssuer {
        JwtIssuer::hs256(SECRET)
    }

    fn make_strategy() -> JwtStrategy {
        JwtStrategy::hs256(SECRET)
    }

    #[tokio::test]
    async fn jwt_strategy_authenticates_valid_token() {
        let issuer = make_issuer();
        let principal = Principal::new("user-42").with_name("Alice");
        let token = issuer.issue(&principal).unwrap();

        let auth = Authenticator::new().with_strategy(make_strategy());
        let context = AuthContext::new().with_field("bearer_token", token);

        let result = auth.authenticate_with("jwt", &context).await.unwrap();
        assert_eq!(result.id, "user-42");
        assert_eq!(result.name.as_deref(), Some("Alice"));
    }

    #[tokio::test]
    async fn jwt_strategy_rejects_tampered_token() {
        let issuer = make_issuer();
        let principal = Principal::new("user-42");
        let token = issuer.issue(&principal).unwrap();

        // Tamper with the payload section of the token.
        let mut parts: Vec<&str> = token.splitn(3, '.').collect();
        parts[1] = "dGFtcGVyZWQ"; // base64("tampered")
        let tampered = parts.join(".");

        let auth = Authenticator::new().with_strategy(make_strategy());
        let context = AuthContext::new().with_field("bearer_token", tampered);

        let err = auth.authenticate_with("jwt", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn jwt_strategy_rejects_missing_token() {
        let auth = Authenticator::new().with_strategy(make_strategy());
        let context = AuthContext::new(); // no bearer_token key

        let err = auth.authenticate_with("jwt", &context).await.unwrap_err();
        assert_eq!(err, AuthError::MissingCredentials);
    }

    #[tokio::test]
    async fn jwt_strategy_preserves_roles() {
        let issuer = make_issuer();
        let principal = Principal::new("admin-1")
            .with_role("admin")
            .with_role("editor");
        let token = issuer.issue(&principal).unwrap();

        let auth = Authenticator::new().with_strategy(make_strategy());
        let context = AuthContext::new().with_field("bearer_token", token);

        let result = auth.authenticate_with("jwt", &context).await.unwrap();
        assert!(result.has_role("admin"));
        assert!(result.has_role("editor"));
        assert!(!result.has_role("viewer"));
    }

    #[tokio::test]
    async fn jwt_strategy_rejects_token_signed_with_different_secret() {
        let other_issuer = JwtIssuer::hs256(b"a-different-secret");
        let principal = Principal::new("user-1");
        let token = other_issuer.issue(&principal).unwrap();

        let auth = Authenticator::new().with_strategy(make_strategy());
        let context = AuthContext::new().with_field("bearer_token", token);

        let err = auth.authenticate_with("jwt", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    // ── Refresh token tests ───────────────────────────────────────────────────────────────────────

    #[test]
    fn issuer_with_refresh_tokens_has_default_expiry() {
        let issuer = JwtIssuer::hs256(SECRET).with_refresh_tokens();
        assert!(issuer.has_refresh_tokens());
    }

    #[test]
    fn issuer_without_refresh_tokens_disabled_by_default() {
        let issuer = JwtIssuer::hs256(SECRET);
        assert!(!issuer.has_refresh_tokens());
    }

    #[test]
    fn issuer_with_refresh_expiry_enables_refresh() {
        let issuer = JwtIssuer::hs256(SECRET).with_refresh_expiry(30 * 24 * 3600);
        assert!(issuer.has_refresh_tokens());
    }

    #[test]
    fn issue_refresh_errors_when_not_enabled() {
        let issuer = JwtIssuer::hs256(SECRET);
        let err = issuer.issue_refresh(&Principal::new("user-1")).unwrap_err();
        assert!(matches!(err, JwtError::RefreshNotEnabled));
    }

    #[tokio::test]
    async fn jwt_strategy_rejects_refresh_token() {
        let issuer = JwtIssuer::hs256(SECRET).with_refresh_tokens();
        let principal = Principal::new("user-42");
        let refresh_token = issuer.issue_refresh(&principal).unwrap();

        let auth = Authenticator::new().with_strategy(make_strategy());
        let context = AuthContext::new().with_field("bearer_token", refresh_token);

        let err = auth.authenticate_with("jwt", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn jwt_refresh_strategy_authenticates_valid_refresh_token() {
        let issuer = JwtIssuer::hs256(SECRET).with_refresh_tokens();
        let principal = Principal::new("user-42").with_name("Alice").with_role("member");
        let refresh_token = issuer.issue_refresh(&principal).unwrap();

        let auth = Authenticator::new().with_strategy(JwtRefreshStrategy::hs256(SECRET));
        let context = AuthContext::new().with_field("refresh_token", refresh_token);

        let result = auth.authenticate_with("jwt-refresh", &context).await.unwrap();
        assert_eq!(result.id, "user-42");
        assert_eq!(result.name.as_deref(), Some("Alice"));
        assert!(result.has_role("member"));
    }

    #[tokio::test]
    async fn jwt_refresh_strategy_rejects_access_token() {
        let issuer = JwtIssuer::hs256(SECRET);
        let principal = Principal::new("user-42");
        let access_token = issuer.issue(&principal).unwrap();

        let auth = Authenticator::new().with_strategy(JwtRefreshStrategy::hs256(SECRET));
        let context = AuthContext::new().with_field("refresh_token", access_token);

        let err = auth.authenticate_with("jwt-refresh", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn jwt_refresh_strategy_rejects_missing_token() {
        let auth = Authenticator::new().with_strategy(JwtRefreshStrategy::hs256(SECRET));
        let context = AuthContext::new();

        let err = auth.authenticate_with("jwt-refresh", &context).await.unwrap_err();
        assert_eq!(err, AuthError::MissingCredentials);
    }

    #[tokio::test]
    async fn jwt_refresh_strategy_rejects_tampered_token() {
        let issuer = JwtIssuer::hs256(SECRET).with_refresh_tokens();
        let principal = Principal::new("user-42");
        let token = issuer.issue_refresh(&principal).unwrap();

        let mut parts: Vec<&str> = token.splitn(3, '.').collect();
        parts[1] = "dGFtcGVyZWQ"; // base64("tampered")
        let tampered = parts.join(".");

        let auth = Authenticator::new().with_strategy(JwtRefreshStrategy::hs256(SECRET));
        let context = AuthContext::new().with_field("refresh_token", tampered);

        let err = auth.authenticate_with("jwt-refresh", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }
}
