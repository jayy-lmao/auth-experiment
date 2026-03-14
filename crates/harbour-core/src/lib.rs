use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

/// Authenticated caller information injected into request handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub name: Option<String>,
}

impl Principal {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Small, framework-agnostic credential bag populated by adapters.
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    fields: HashMap<String, String>,
}

impl AuthContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("missing credentials")]
    MissingCredentials,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("strategy not found: {0}")]
    StrategyNotFound(String),
}

#[async_trait]
pub trait Strategy: Send + Sync {
    async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError>;
}

/// Auth service with a strategy registry and a default strategy.
#[derive(Clone, Default)]
pub struct Authenticator {
    strategies: HashMap<String, Arc<dyn Strategy>>,
    default_strategy: Option<String>,
}

impl Authenticator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_strategy(
        mut self,
        strategy_name: impl Into<String>,
        strategy: impl Strategy + 'static,
    ) -> Self {
        self.register_strategy(strategy_name, strategy);
        self
    }

    pub fn register_strategy(
        &mut self,
        strategy_name: impl Into<String>,
        strategy: impl Strategy + 'static,
    ) {
        let strategy_name = strategy_name.into();
        if self.default_strategy.is_none() {
            self.default_strategy = Some(strategy_name.clone());
        }
        self.strategies.insert(strategy_name, Arc::new(strategy));
    }

    pub fn set_default_strategy(&mut self, strategy_name: impl Into<String>) {
        self.default_strategy = Some(strategy_name.into());
    }

    pub async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError> {
        let strategy_name = self
            .default_strategy
            .as_deref()
            .ok_or_else(|| AuthError::StrategyNotFound("<default>".to_string()))?;

        self.authenticate_with(strategy_name, context).await
    }

    pub async fn authenticate_with(
        &self,
        strategy_name: &str,
        context: &AuthContext,
    ) -> Result<Principal, AuthError> {
        let strategy = self
            .strategies
            .get(strategy_name)
            .ok_or_else(|| AuthError::StrategyNotFound(strategy_name.to_string()))?;

        strategy.authenticate(context).await
    }
}

/// Deterministic bearer strategy for the Harbour MVP.
pub struct StaticBearerStrategy {
    token: String,
    principal: Principal,
}

impl StaticBearerStrategy {
    pub fn new(token: impl Into<String>, principal: Principal) -> Self {
        Self {
            token: token.into(),
            principal,
        }
    }
}

#[async_trait]
impl Strategy for StaticBearerStrategy {
    async fn authenticate(&self, context: &AuthContext) -> Result<Principal, AuthError> {
        let token = context
            .get("bearer_token")
            .ok_or(AuthError::MissingCredentials)?;

        if token == self.token {
            Ok(self.principal.clone())
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_bearer_authenticates_with_matching_token() {
        let auth = Authenticator::new().with_strategy(
            "bearer",
            StaticBearerStrategy::new("secret", Principal::new("user-1")),
        );
        let context = AuthContext::new().with_field("bearer_token", "secret");

        let principal = auth.authenticate(&context).await.unwrap();
        assert_eq!(principal.id, "user-1");
    }

    #[tokio::test]
    async fn static_bearer_rejects_bad_token() {
        let auth = Authenticator::new().with_strategy(
            "bearer",
            StaticBearerStrategy::new("secret", Principal::new("user-1")),
        );
        let context = AuthContext::new().with_field("bearer_token", "wrong");

        let err = auth.authenticate(&context).await.unwrap_err();
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn can_select_specific_registered_strategy() {
        let mut auth = Authenticator::new()
            .with_strategy(
                "user",
                StaticBearerStrategy::new("user-token", Principal::new("user-1")),
            )
            .with_strategy(
                "admin",
                StaticBearerStrategy::new("admin-token", Principal::new("admin-1")),
            );
        auth.set_default_strategy("user");

        let context = AuthContext::new().with_field("bearer_token", "admin-token");

        let principal = auth.authenticate_with("admin", &context).await.unwrap();
        assert_eq!(principal.id, "admin-1");
    }
}
