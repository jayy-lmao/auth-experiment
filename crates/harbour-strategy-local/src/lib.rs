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

        let auth = Authenticator::new().with_strategy("local", strategy);
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

        let auth = Authenticator::new().with_strategy("local", strategy);
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

        let auth = Authenticator::new().with_strategy("local", strategy);
        let context = AuthContext::new()
            .with_field(IDENTIFIER_KEY, "alice")
            .with_field(PASSWORD_KEY, "secret");

        let principal = auth.authenticate_with("local", &context).await.unwrap();
        assert_eq!(principal.id, "user-1");
    }
}
