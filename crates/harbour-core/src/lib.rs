use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

/// Type-safe strategy identifier.
///
/// Implement this trait on an application-defined enum to avoid bare string strategy names:
///
/// ```rust
/// use harbour_core::StrategyName;
///
/// enum MyStrategy { User, Admin, Local }
///
/// impl StrategyName for MyStrategy {
///     fn strategy_name(&self) -> &str {
///         match self {
///             Self::User => "user",
///             Self::Admin => "admin",
///             Self::Local => "local",
///         }
///     }
/// }
/// ```
pub trait StrategyName {
    fn strategy_name(&self) -> &str;
}

impl StrategyName for str {
    fn strategy_name(&self) -> &str {
        self
    }
}

impl StrategyName for String {
    fn strategy_name(&self) -> &str {
        self.as_str()
    }
}

impl<T: StrategyName + ?Sized> StrategyName for &T {
    fn strategy_name(&self) -> &str {
        (**self).strategy_name()
    }
}

/// Authenticated caller information injected into request handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub name: Option<String>,
    /// Roles assigned to this principal, used for role-based access control (RBAC).
    pub roles: Vec<String>,
}

impl Principal {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            roles: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add a role to this principal.
    ///
    /// ```rust
    /// use harbour_core::Principal;
    ///
    /// let p = Principal::new("user-1").with_role("admin").with_role("editor");
    /// assert!(p.has_role("admin"));
    /// assert!(!p.has_role("viewer"));
    /// ```
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Returns `true` if this principal has the given role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
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
        strategy_name: impl StrategyName,
        strategy: impl Strategy + 'static,
    ) -> Self {
        self.register_strategy(strategy_name, strategy);
        self
    }

    pub fn register_strategy(
        &mut self,
        strategy_name: impl StrategyName,
        strategy: impl Strategy + 'static,
    ) {
        let strategy_name = strategy_name.strategy_name().to_string();
        if self.default_strategy.is_none() {
            self.default_strategy = Some(strategy_name.clone());
        }
        self.strategies.insert(strategy_name, Arc::new(strategy));
    }

    pub fn set_default_strategy(&mut self, strategy_name: impl StrategyName) {
        self.default_strategy = Some(strategy_name.strategy_name().to_string());
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
        strategy_name: impl StrategyName,
        context: &AuthContext,
    ) -> Result<Principal, AuthError> {
        let name = strategy_name.strategy_name();
        let strategy = self
            .strategies
            .get(name)
            .ok_or_else(|| AuthError::StrategyNotFound(name.to_string()))?;

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

    #[test]
    fn principal_roles_can_be_assigned_and_checked() {
        let p = Principal::new("user-1")
            .with_name("Alice")
            .with_role("admin")
            .with_role("editor");
        assert!(p.has_role("admin"));
        assert!(p.has_role("editor"));
        assert!(!p.has_role("viewer"));
    }

    #[test]
    fn principal_has_empty_roles_by_default() {
        let p = Principal::new("user-1");
        assert!(p.roles.is_empty());
        assert!(!p.has_role("admin"));
    }

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
