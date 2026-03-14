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
    async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError> {
        let token = context
            .get("bearer_token")
            .ok_or(AuthError::MissingCredentials)?;

        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|_| AuthError::InvalidCredentials)?;

        Ok(token_data.claims.into())
    }
}

/// Default token lifetime used by [`JwtIssuer`] when no expiry is specified.
///
/// Override with [`JwtIssuer::with_expiry`] when a different lifetime is needed.
pub const DEFAULT_TOKEN_EXPIRY_SECS: u64 = 3600; // 1 hour

/// Issues signed JWTs that can be verified by [`JwtStrategy`].
///
/// Intended for use in login handlers — typically via [`HarbourAuth::with_jwt_issuer`] in the
/// Axum adapter, which wires everything up automatically.
///
/// ## Example
///
/// ```rust,ignore
/// use harbour_strategy_jwt::JwtIssuer;
/// use harbour_core::Principal;
///
/// // 1-hour expiry by default:
/// let issuer = JwtIssuer::hs256(b"super-secret-key");
///
/// // Override when needed:
/// let issuer = JwtIssuer::hs256(b"super-secret-key").with_expiry(7 * 24 * 3600); // 1 week
///
/// let token = issuer.issue(&Principal::new("user-1").with_name("Alice")).unwrap();
/// ```
pub struct JwtIssuer {
    encoding_key: EncodingKey,
    header: Header,
    expiry_secs: u64,
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
        })
    }

    /// Override the token lifetime.
    ///
    /// ```rust,ignore
    /// // Tokens valid for 7 days:
    /// let issuer = JwtIssuer::hs256(secret).with_expiry(7 * 24 * 3600);
    /// ```
    pub fn with_expiry(mut self, expiry_secs: u64) -> Self {
        self.expiry_secs = expiry_secs;
        self
    }

    /// Issue a signed JWT for the given [`Principal`].
    ///
    /// The token encodes the principal's `id`, `name`, and `roles` as standard
    /// JWT claims (`sub`, `name`, `roles`), plus `iat` and `exp`.
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
        };

        encode(&self.header, &claims, &self.encoding_key).map_err(JwtError::Encoding)
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

        let auth = Authenticator::new().with_strategy("jwt", make_strategy());
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

        let auth = Authenticator::new().with_strategy("jwt", make_strategy());
        let context = AuthContext::new().with_field("bearer_token", tampered);

        let err = auth.authenticate_with("jwt", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn jwt_strategy_rejects_missing_token() {
        let auth = Authenticator::new().with_strategy("jwt", make_strategy());
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

        let auth = Authenticator::new().with_strategy("jwt", make_strategy());
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

        let auth = Authenticator::new().with_strategy("jwt", make_strategy());
        let context = AuthContext::new().with_field("bearer_token", token);

        let err = auth.authenticate_with("jwt", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }
}
