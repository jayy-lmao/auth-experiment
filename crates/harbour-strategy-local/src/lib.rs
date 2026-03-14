use async_trait::async_trait;
use harbour_core::{AuthContext, AuthError, Principal, Strategy};
use std::collections::HashMap;

pub const IDENTIFIER_KEY: &str = "local.identifier";
pub const PASSWORD_KEY: &str = "local.password";

#[derive(Debug, Clone)]
pub struct LocalUserRecord {
    pub principal: Principal,
    pub password_hash: String,
}

impl LocalUserRecord {
    pub fn new(principal: Principal, password_hash: impl Into<String>) -> Self {
        Self {
            principal,
            password_hash: password_hash.into(),
        }
    }
}

#[async_trait]
pub trait LocalUserStore: Send + Sync {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<LocalUserRecord>, AuthError>;
}

pub trait PasswordVerifier: Send + Sync {
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, AuthError>;
}

pub struct LocalStrategy<S, V>
where
    S: LocalUserStore,
    V: PasswordVerifier,
{
    store: S,
    verifier: V,
}

impl<S, V> LocalStrategy<S, V>
where
    S: LocalUserStore,
    V: PasswordVerifier,
{
    pub fn new(store: S, verifier: V) -> Self {
        Self { store, verifier }
    }
}

#[async_trait]
impl<S, V> Strategy for LocalStrategy<S, V>
where
    S: LocalUserStore,
    V: PasswordVerifier,
{
    fn strategy_name(&self) -> &str {
        "local"
    }

    async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError> {
        let identifier = context
            .get(IDENTIFIER_KEY)
            .ok_or(AuthError::MissingCredentials)?;
        let password = context
            .get(PASSWORD_KEY)
            .ok_or(AuthError::MissingCredentials)?;

        let Some(user) = self.store.find_by_identifier(identifier).await? else {
            return Err(AuthError::InvalidCredentials);
        };

        if self.verifier.verify(password, &user.password_hash)? {
            Ok(user.principal)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}

#[derive(Default)]
pub struct InMemoryUserStore {
    users: HashMap<String, LocalUserRecord>,
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user(
        mut self,
        identifier: impl Into<String>,
        principal: Principal,
        password_hash: impl Into<String>,
    ) -> Self {
        self.users.insert(
            identifier.into(),
            LocalUserRecord::new(principal, password_hash),
        );
        self
    }
}

#[async_trait]
impl LocalUserStore for InMemoryUserStore {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<LocalUserRecord>, AuthError> {
        Ok(self.users.get(identifier).cloned())
    }
}

/// Simple verifier for tests/examples. Production applications should use a real hash verifier.
pub struct PlaintextPasswordVerifier;

impl PasswordVerifier for PlaintextPasswordVerifier {
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, AuthError> {
        Ok(password == password_hash)
    }
}

/// Production-grade password verifier using the Argon2id algorithm.
///
/// Requires the `argon2` feature to be enabled.
///
/// ## Usage
///
/// ```rust,ignore
/// use harbour_strategy_local::{Argon2PasswordVerifier, Argon2PasswordHasher};
///
/// // Hash a password at registration time:
/// let hash = Argon2PasswordHasher::hash_password("hunter2").unwrap();
///
/// // Store `hash` in your database. Later, verify it:
/// let verifier = Argon2PasswordVerifier;
/// assert!(verifier.verify("hunter2", &hash).unwrap());
/// ```
#[cfg(feature = "argon2")]
pub struct Argon2PasswordVerifier;

#[cfg(feature = "argon2")]
impl PasswordVerifier for Argon2PasswordVerifier {
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, AuthError> {
        use argon2::{Argon2, PasswordHash, PasswordVerifier as _};

        let parsed_hash =
            PasswordHash::new(password_hash).map_err(|_| AuthError::InvalidCredentials)?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

/// Helper for hashing passwords with Argon2id at user-registration time.
///
/// Requires the `argon2` feature to be enabled.
#[cfg(feature = "argon2")]
pub struct Argon2PasswordHasher;

#[cfg(feature = "argon2")]
impl Argon2PasswordHasher {
    /// Hash `password` using Argon2id with a random salt.
    ///
    /// Store the returned PHC-format string in your user store.
    /// Verify it later with [`Argon2PasswordVerifier`].
    pub fn hash_password(password: &str) -> Result<String, AuthError> {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher as _};
        use rand_core::OsRng;

        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|_| AuthError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbour_core::Authenticator;

    struct PrefixVerifier;

    impl PasswordVerifier for PrefixVerifier {
        fn verify(&self, password: &str, password_hash: &str) -> Result<bool, AuthError> {
            Ok(password_hash == format!("custom::{password}"))
        }
    }

    #[tokio::test]
    async fn local_strategy_authenticates_valid_user() {
        let store = InMemoryUserStore::new().with_user(
            "alice",
            Principal::new("user-1").with_name("Alice"),
            "secret",
        );
        let strategy = LocalStrategy::new(store, PlaintextPasswordVerifier);

        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new()
            .with_field(IDENTIFIER_KEY, "alice")
            .with_field(PASSWORD_KEY, "secret");

        let principal = auth.authenticate_with("local", &context).await.unwrap();
        assert_eq!(principal.id, "user-1");
    }

    #[tokio::test]
    async fn local_strategy_rejects_unknown_user() {
        let store = InMemoryUserStore::new();
        let strategy = LocalStrategy::new(store, PlaintextPasswordVerifier);

        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new()
            .with_field(IDENTIFIER_KEY, "bob")
            .with_field(PASSWORD_KEY, "secret");

        let err = auth.authenticate_with("local", &context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn local_strategy_supports_custom_verifier_patterns() {
        let store = InMemoryUserStore::new().with_user(
            "alice",
            Principal::new("user-1").with_name("Alice"),
            "custom::secret",
        );
        let strategy = LocalStrategy::new(store, PrefixVerifier);

        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new()
            .with_field(IDENTIFIER_KEY, "alice")
            .with_field(PASSWORD_KEY, "secret");

        let principal = auth.authenticate_with("local", &context).await.unwrap();
        assert_eq!(principal.id, "user-1");
    }

    #[cfg(feature = "argon2")]
    #[tokio::test]
    async fn argon2_verifier_accepts_correct_password() {
        use crate::{Argon2PasswordHasher, Argon2PasswordVerifier};

        let hash = Argon2PasswordHasher::hash_password("hunter2").unwrap();
        let verifier = Argon2PasswordVerifier;
        assert!(verifier.verify("hunter2", &hash).unwrap());
    }

    #[cfg(feature = "argon2")]
    #[tokio::test]
    async fn argon2_verifier_rejects_wrong_password() {
        use crate::{Argon2PasswordHasher, Argon2PasswordVerifier};

        let hash = Argon2PasswordHasher::hash_password("hunter2").unwrap();
        let verifier = Argon2PasswordVerifier;
        assert!(!verifier.verify("wrong_password", &hash).unwrap());
    }

    #[cfg(feature = "argon2")]
    #[tokio::test]
    async fn argon2_strategy_authenticates_valid_user() {
        use crate::{Argon2PasswordHasher, Argon2PasswordVerifier};

        let hash = Argon2PasswordHasher::hash_password("s3cur3pass").unwrap();
        let store = InMemoryUserStore::new().with_user(
            "bob",
            Principal::new("user-2").with_name("Bob"),
            hash,
        );
        let strategy = LocalStrategy::new(store, Argon2PasswordVerifier);

        let auth = Authenticator::new().with_strategy(strategy);
        let context = AuthContext::new()
            .with_field(IDENTIFIER_KEY, "bob")
            .with_field(PASSWORD_KEY, "s3cur3pass");

        let principal = auth.authenticate_with("local", &context).await.unwrap();
        assert_eq!(principal.id, "user-2");
    }
}
