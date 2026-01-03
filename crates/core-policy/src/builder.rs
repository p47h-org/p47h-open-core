//! Builder pattern for ergonomic policy construction

use crate::context_expr::ContextExpr;
use crate::error::{PolicyError, Result};
use crate::policy::{Action, Policy, PolicyRule, Resource};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Builder for creating `PolicyRule` instances with a fluent API
///
/// # Examples
///
/// ```
/// use core_policy::builder::PolicyRuleBuilder;
/// use core_policy::{Action, Resource};
///
/// # fn example() -> Result<(), core_policy::PolicyError> {
/// // Basic RBAC rule
/// let rule = PolicyRuleBuilder::new()
///     .for_peer("12D3KooWXYZ...")
///     .allow(Action::Read)
///     .on(Resource::File("/docs/*".into()))
///     .build()
///     .unwrap();
///
/// // ABAC rule with expiration
/// let rule = PolicyRuleBuilder::new()
///     .for_peer("technician")
///     .allow(Action::Read)
///     .on(Resource::File("/logs/*".into()))
///     .expires_at(1762348800)
///     .build()
///     .unwrap();
///
/// // ABAC rule with attributes
/// let rule = PolicyRuleBuilder::new()
///     .for_peer("alice")
///     .allow(Action::Write)
///     .on(Resource::File("/shared/*".into()))
///     .with_attribute("location", "office")
///     .with_attribute("security_level", "high")
///     .build()
///     .unwrap();
///
/// // ABAC rule with context expression (advanced)
/// let rule = PolicyRuleBuilder::new()
///     .for_peer("alice")
///     .allow(Action::Read)
///     .on(Resource::File("/sensitive/*".into()))
///     .with_context_expr("role == \"admin\" AND department == \"IT\"")?  // Returns Result
///     .build()
///     .unwrap();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct PolicyRuleBuilder {
    peer_id: Option<String>,
    action: Option<Action>,
    resource: Option<Resource>,
    expires_at: Option<u64>,
    attributes: BTreeMap<String, String>,
    context_expr: Option<ContextExpr>,
}

impl PolicyRuleBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the peer ID that this rule applies to
    #[must_use]
    pub fn for_peer(mut self, peer_id: impl Into<String>) -> Self {
        self.peer_id = Some(peer_id.into());
        self
    }

    /// Set the action allowed by this rule
    #[must_use]
    pub fn allow(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the resource this rule applies to
    #[must_use]
    pub fn on(mut self, resource: Resource) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Set the expiration timestamp (Unix seconds) - ABAC
    #[must_use]
    pub const fn expires_at(mut self, timestamp: u64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Add an attribute for contextual access control - ABAC (legacy)
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Add a context expression for advanced ABAC (boolean logic)
    ///
    /// # Arguments
    ///
    /// * `expr` - Expression string to parse (e.g., "role == \"admin\" AND department == \"IT\"")
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidExpression` if the expression syntax is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use core_policy::builder::PolicyRuleBuilder;
    /// use core_policy::{Action, Resource};
    ///
    /// # fn example() -> Result<(), core_policy::PolicyError> {
    /// let rule = PolicyRuleBuilder::new()
    ///     .for_peer("alice")
    ///     .allow(Action::Read)
    ///     .on(Resource::All)
    ///     .with_context_expr("role == \"admin\" AND active == \"true\"")?  // Returns Result
    ///     .build()
    ///     .unwrap();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_context_expr(mut self, expr: impl AsRef<str>) -> Result<Self> {
        let parsed = ContextExpr::parse(expr.as_ref())?;
        self.context_expr = Some(parsed);
        Ok(self)
    }

    /// Build the `PolicyRule`, returning an error if required fields are missing
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidRule` if any required field is missing:
    /// - `peer_id`
    /// - `action`
    /// - `resource`
    pub fn build(self) -> Result<PolicyRule> {
        let peer_id = self
            .peer_id
            .ok_or_else(|| PolicyError::InvalidRule("peer_id is required".to_string()))?;

        let action = self
            .action
            .ok_or_else(|| PolicyError::InvalidRule("action is required".to_string()))?;

        let resource = self
            .resource
            .ok_or_else(|| PolicyError::InvalidRule("resource is required".to_string()))?;

        Ok(PolicyRule {
            peer_id,
            action,
            resource,
            expires_at: self.expires_at,
            attributes: self.attributes,
            context_expr: self.context_expr,
        })
    }
}

/// Builder for creating Policy instances with a fluent API
///
/// # Examples
///
/// ```
/// use core_policy::{PolicyBuilder, PolicyRuleBuilder, Action, Resource};
///
/// let policy = PolicyBuilder::new("admin-policy")
///     .add_rule_with(|rule| {
///         rule.for_peer("12D3KooWAlice...")
///             .allow(Action::All)
///             .on(Resource::All)
///     })
///     .add_rule_with(|rule| {
///         rule.for_peer("12D3KooWBob...")
///             .allow(Action::Read)
///             .on(Resource::File("/docs/*".into()))
///     })
///     .with_metadata("owner", "alice")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct PolicyBuilder {
    name: String,
    valid_duration_secs: u64,
    rules: Vec<PolicyRule>,
    metadata: BTreeMap<String, String>,
    timestamp: Option<u64>,
}

impl PolicyBuilder {
    /// Create a new policy builder with default validity (30 days)
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            timestamp: None,
            name: name.into(),
            rules: Vec::new(),
            metadata: BTreeMap::new(),
            valid_duration_secs: 30 * 24 * 60 * 60,
        }
    }

    /// Set the policy issuance timestamp (Unix seconds).
    ///
    /// Required for valid time-based policies. If not set, defaults to 0.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Set policy validity duration in seconds
    #[must_use]
    pub const fn valid_for(mut self, duration_secs: u64) -> Self {
        self.valid_duration_secs = duration_secs;
        self
    }

    /// Add a rule using a builder function
    #[must_use]
    pub fn add_rule_with<F>(mut self, f: F) -> Self
    where
        F: FnOnce(PolicyRuleBuilder) -> PolicyRuleBuilder,
    {
        let builder = f(PolicyRuleBuilder::new());
        if let Ok(rule) = builder.build() {
            self.rules.push(rule);
        }
        self
    }

    /// Add a pre-constructed rule
    #[must_use]
    pub fn add_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Add metadata to the policy
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the Policy, returning an error if validation fails
    ///
    /// # Errors
    ///
    /// Returns an error if policy validation fails (see `Policy::validate()`)
    pub fn build(self) -> Result<Policy> {
        let now = self.timestamp.unwrap_or(0);
        let mut policy = Policy::new(self.name, self.valid_duration_secs, now)?;

        // Add all rules
        for rule in self.rules {
            policy = policy.add_rule(rule)?;
        }

        // Add all metadata
        for (key, value) in self.metadata {
            policy = policy.with_metadata(key, value);
        }

        policy.validate()?;
        Ok(policy)
    }
}

// Convenience methods for Action construction
impl Action {
    /// Create a Read action
    #[must_use]
    pub const fn read() -> Self {
        Self::Read
    }

    /// Create a Write action
    #[must_use]
    pub const fn write() -> Self {
        Self::Write
    }

    /// Create an Execute action
    #[must_use]
    pub const fn execute() -> Self {
        Self::Execute
    }

    /// Create a Delete action
    #[must_use]
    pub const fn delete() -> Self {
        Self::Delete
    }

    /// Create an All action (wildcard)
    #[must_use]
    pub const fn all() -> Self {
        Self::All
    }

    /// Create a custom action
    #[must_use]
    pub fn custom(name: impl Into<String>) -> Self {
        Self::Custom(name.into())
    }
}

// Convenience methods for Resource construction
impl Resource {
    /// Create a File resource
    #[must_use]
    pub fn file(path: impl Into<String>) -> Self {
        Self::File(path.into())
    }

    /// Create a USB device resource
    #[must_use]
    pub fn usb(device: impl Into<String>) -> Self {
        Self::Usb(device.into())
    }

    /// Create a Tunnel resource
    #[must_use]
    pub fn tunnel(name: impl Into<String>) -> Self {
        Self::Tunnel(name.into())
    }

    /// Create an All resource (wildcard)
    #[must_use]
    pub const fn all() -> Self {
        Self::All
    }

    /// Create a custom resource
    #[must_use]
    pub fn custom(resource_type: impl Into<String>, path: impl Into<String>) -> Self {
        Self::Custom {
            resource_type: resource_type.into(),
            path: path.into(),
        }
    }
}
