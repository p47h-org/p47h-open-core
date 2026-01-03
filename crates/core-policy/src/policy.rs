//! Policy definitions and validation logic
//!
//! This module provides the core domain types for RBAC/ABAC authorization:
//! - `Action`: What operations can be performed
//! - `Resource`: What can be accessed
//! - `PolicyRule`: Individual authorization rule
//! - `Policy`: Collection of rules with versioning
//!
//! ## Security Constraints
//!
//! The following limits are enforced to prevent resource exhaustion:
//! - `MAX_RULES_PER_POLICY` (1024): Maximum rules per policy
//! - `MAX_POLICY_NAME_LENGTH` (128): Maximum policy name length
//! - `MAX_RESOURCE_PATTERN_LENGTH` (256): Maximum pattern length

use crate::context_expr::ContextExpr;
use crate::error::{PolicyError, Result};
use crate::path::PathPattern;
use crate::{MAX_POLICY_NAME_LENGTH, MAX_RULES_PER_POLICY};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Action that can be performed on a resource
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Execute access
    Execute,
    /// Delete access
    Delete,
    /// All actions
    All,
    /// Custom action
    Custom(String),
}

impl Action {
    /// Check if this action matches another action (considering wildcards)
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::All, _) | (_, Self::All) => true,
            (a, b) => a == b,
        }
    }
}

/// Resource that can be accessed
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resource {
    /// File system path
    File(String),
    /// USB device
    Usb(String),
    /// Network tunnel
    Tunnel(String),
    /// All resources
    All,
    /// Custom resource
    Custom {
        /// Resource type identifier
        resource_type: String,
        /// Resource path
        path: String,
    },
}

impl Resource {
    /// Check if this resource matches another resource (considering wildcards)
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::All, _) | (_, Self::All) => true,
            (Self::File(pattern), Self::File(path)) => {
                // Use unchecked since patterns in existing resources are assumed valid
                PathPattern::new_unchecked(pattern).matches(path)
            }
            (Self::Usb(pattern), Self::Usb(device)) => {
                PathPattern::new_unchecked(pattern).matches(device)
            }
            (Self::Tunnel(pattern), Self::Tunnel(name)) => {
                PathPattern::new_unchecked(pattern).matches(name)
            }
            (
                Self::Custom {
                    resource_type: t1,
                    path: p1,
                },
                Self::Custom {
                    resource_type: t2,
                    path: p2,
                },
            ) => t1 == t2 && PathPattern::new_unchecked(p1).matches(p2),
            _ => false,
        }
    }
}

/// A single policy rule with optional ABAC (Attribute-Based Access Control) features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Peer ID that this rule applies to
    pub peer_id: String,
    /// Action allowed by this rule
    pub action: Action,
    /// Resource this rule applies to
    pub resource: Resource,

    // ===== ABAC Features =====
    /// Optional expiration timestamp (Unix seconds)
    /// If set, the rule is only valid before this time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Optional context attributes for conditional access (legacy - simple key-value matching)
    /// Examples: {"location": "office", "security_level": "high"}
    ///
    /// Uses BTreeMap for deterministic serialization (cryptographic safety)
    ///
    /// **Note:** This is the legacy ABAC mechanism. For complex boolean logic,
    /// use `context_expr` instead.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,

    /// Optional context expression for advanced ABAC (boolean logic)
    ///
    /// This provides more powerful conditional logic than simple attribute matching:
    /// - Boolean operators: AND, OR, NOT
    /// - Comparison operators: ==, !=, <, <=, >, >=
    /// - Attribute existence checks: HAS
    ///
    /// Examples:
    /// - `role == "admin" AND department == "IT"`
    /// - `(role == "admin" OR role == "moderator") AND active == "true"`
    /// - `NOT (status == "banned")`
    ///
    /// When both `attributes` and `context_expr` are present, **both** must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_expr: Option<ContextExpr>,
}

impl PolicyRule {
    /// Create a new policy rule with basic RBAC
    #[must_use]
    pub fn new(peer_id: String, action: Action, resource: Resource) -> Self {
        Self {
            peer_id,
            action,
            resource,
            expires_at: None,
            attributes: BTreeMap::new(),
            context_expr: None,
        }
    }

    /// Create a new policy rule with expiration (ABAC)
    #[must_use]
    pub fn with_expiration(
        peer_id: String,
        action: Action,
        resource: Resource,
        expires_at: u64,
    ) -> Self {
        Self {
            peer_id,
            action,
            resource,
            expires_at: Some(expires_at),
            attributes: BTreeMap::new(),
            context_expr: None,
        }
    }

    /// Create a new policy rule with attributes (ABAC)
    #[must_use]
    pub const fn with_attributes(
        peer_id: String,
        action: Action,
        resource: Resource,
        attributes: BTreeMap<String, String>,
    ) -> Self {
        Self {
            peer_id,
            action,
            resource,
            expires_at: None,
            attributes,
            context_expr: None,
        }
    }

    /// Add an expiration time to this rule
    #[must_use]
    pub const fn expires_at(mut self, timestamp: u64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Add an attribute to this rule
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Add a context expression to this rule (advanced ABAC)
    ///
    /// # Example
    ///
    /// ```
    /// use core_policy::{PolicyRule, Action, Resource, ContextExpr};
    ///
    /// let rule = PolicyRule::new("alice".into(), Action::Read, Resource::All)
    ///     .with_context_expr(ContextExpr::parse("role == \"admin\"").unwrap());
    /// ```
    #[must_use]
    pub fn with_context_expr(mut self, expr: ContextExpr) -> Self {
        self.context_expr = Some(expr);
        self
    }

    /// Check if this rule has expired
    #[must_use]
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at.is_some_and(|exp| current_time >= exp)
    }

    /// Check if this rule's attributes match the given context
    ///
    /// This method evaluates both legacy attribute matching and the new context expression:
    /// 1. If `attributes` is non-empty, all attributes must match (legacy behavior)
    /// 2. If `context_expr` is present, it must evaluate to true
    /// 3. Both conditions must be satisfied if both are present
    ///
    /// Returns true if all context constraints match.
    #[must_use]
    pub fn matches_context(&self, context: &BTreeMap<String, String>) -> bool {
        // Legacy attribute matching (simple key-value equality)
        let attributes_match = if self.attributes.is_empty() {
            true // No constraints = always matches
        } else {
            // All rule attributes must be present in context and match
            self.attributes
                .iter()
                .all(|(key, value)| context.get(key) == Some(value))
        };

        // New context expression evaluation (boolean logic)
        let expr_match = match &self.context_expr {
            None => true, // No expression = always matches
            Some(expr) => {
                // Evaluate expression with depth 0 (start of recursion)
                // If evaluation fails (e.g., too deep), treat as non-match for security
                expr.evaluate(context, 0).unwrap_or(false)
            }
        };

        // Both must match
        attributes_match && expr_match
    }

    /// Check if this rule allows a specific action on a resource for a peer
    /// Basic RBAC check (no time or context validation)
    #[must_use]
    pub fn allows(&self, peer_id: &str, action: &Action, resource: &Resource) -> bool {
        self.peer_id == peer_id && self.action.matches(action) && self.resource.matches(resource)
    }

    /// Check if this rule allows a specific action on a resource for a peer
    /// Includes time-based and attribute-based checks
    #[must_use]
    pub fn allows_with_context(
        &self,
        peer_id: &str,
        action: &Action,
        resource: &Resource,
        current_time: u64,
        context: &BTreeMap<String, String>,
    ) -> bool {
        // Basic RBAC check
        if !self.allows(peer_id, action, resource) {
            return false;
        }

        // Time-based check (if rule has expiration)
        if self.is_expired(current_time) {
            return false;
        }

        // Attribute-based check (if rule has attributes)
        if !self.matches_context(context) {
            return false;
        }

        true
    }
}

/// A policy containing multiple rules
///
/// # Security
///
/// Fields are private to enforce validation through deserialization.
/// Use `Policy::new()` or deserialize from TOML/JSON to create instances.
/// The `#[serde(try_from)]` attribute ensures all deserialized policies
/// are validated against T20 limits (max rules, max name length, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "PolicyRaw")]
pub struct Policy {
    /// Policy name/identifier
    name: String,

    // ===== Version Control =====
    /// Policy version (monotonic counter, starts at 1)
    version: u64,

    /// Unix timestamp when this policy was issued
    issued_at: u64,

    /// Unix timestamp when this policy expires
    valid_until: u64,

    /// List of policy rules
    rules: Vec<PolicyRule>,

    /// Metadata (uses BTreeMap for deterministic serialization)
    metadata: BTreeMap<String, String>,
}

fn default_version() -> u64 {
    1
}

/// Raw policy structure for deserialization (internal use only)
///
/// This struct is used as an intermediate representation during deserialization.
/// After parsing, it is converted to `Policy` via `TryFrom<PolicyRaw>`, which
/// performs validation to enforce T20 limits.
///
/// This pattern ensures that **all** deserialized policies are validated,
/// preventing DoS attacks through maliciously crafted policy files.
#[derive(Debug, Clone, Deserialize)]
struct PolicyRaw {
    name: String,
    #[serde(default = "default_version")]
    version: u64,
    #[serde(default)]
    issued_at: u64,
    #[serde(default)]
    valid_until: u64,
    rules: Vec<PolicyRule>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

/// Convert PolicyRaw to Policy with validation
///
/// This is called automatically during deserialization due to the
/// `#[serde(try_from = "PolicyRaw")]` attribute on `Policy`.
///
/// # Errors
///
/// Returns `PolicyError` if validation fails:
/// - `TooManyRules`: More than `MAX_RULES_PER_POLICY` rules
/// - `NameTooLong`: Policy name exceeds `MAX_POLICY_NAME_LENGTH`
/// - `InvalidRule`: Other validation failures (empty name, no rules, etc.)
impl TryFrom<PolicyRaw> for Policy {
    type Error = PolicyError;

    fn try_from(raw: PolicyRaw) -> Result<Self> {
        // T20 mitigation: Enforce maximum name length
        if raw.name.len() > MAX_POLICY_NAME_LENGTH {
            return Err(PolicyError::NameTooLong {
                max: MAX_POLICY_NAME_LENGTH,
                length: raw.name.len(),
            });
        }

        // T20 mitigation: Enforce maximum rules
        if raw.rules.len() > MAX_RULES_PER_POLICY {
            return Err(PolicyError::TooManyRules {
                max: MAX_RULES_PER_POLICY,
                attempted: raw.rules.len(),
            });
        }

        // Create policy instance
        let policy = Policy {
            name: raw.name,
            version: raw.version,
            issued_at: raw.issued_at,
            valid_until: raw.valid_until,
            rules: raw.rules,
            metadata: raw.metadata,
        };

        // Run additional validation
        policy.validate()?;

        Ok(policy)
    }
}

impl Policy {
    // ===== Accessors =====

    /// Get the policy name
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the policy version
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Get the issuance timestamp
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Get the expiration timestamp
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Get a reference to the policy rules
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Get a reference to the metadata
    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    // ===== Constructors =====

    /// Create a new empty policy with version 1
    ///
    /// # Arguments
    ///
    /// * `name` - Policy identifier
    /// * `valid_duration_secs` - How long this policy is valid (in seconds)
    /// * `current_time` - Current Unix timestamp (injected for purity/determinism)
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::NameTooLong` if name exceeds `MAX_POLICY_NAME_LENGTH`
    pub fn new(
        name: impl Into<String>,
        valid_duration_secs: u64,
        current_time: u64,
    ) -> Result<Self> {
        let name = name.into();

        // T20 mitigation: Enforce maximum name length
        if name.len() > MAX_POLICY_NAME_LENGTH {
            return Err(PolicyError::NameTooLong {
                max: MAX_POLICY_NAME_LENGTH,
                length: name.len(),
            });
        }

        Ok(Self {
            name,
            version: 1,
            issued_at: current_time,
            valid_until: current_time + valid_duration_secs,
            rules: Vec::new(),
            metadata: BTreeMap::new(),
        })
    }

    /// Create a policy without timestamps (for testing/legacy)
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::NameTooLong` if name exceeds `MAX_POLICY_NAME_LENGTH`
    pub fn new_unversioned(name: impl Into<String>) -> Result<Self> {
        let name = name.into();

        // T20 mitigation: Enforce maximum name length
        if name.len() > MAX_POLICY_NAME_LENGTH {
            return Err(PolicyError::NameTooLong {
                max: MAX_POLICY_NAME_LENGTH,
                length: name.len(),
            });
        }

        Ok(Self {
            name,
            version: 1,
            issued_at: 0,
            valid_until: 2_000_000_000, // Year 2033 (reasonable far future)
            rules: Vec::new(),
            metadata: BTreeMap::new(),
        })
    }

    /// Add a rule to this policy
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::TooManyRules` if adding this rule would exceed `MAX_RULES_PER_POLICY`
    pub fn add_rule(mut self, rule: PolicyRule) -> Result<Self> {
        // T20 mitigation: Enforce maximum rules
        if self.rules.len() >= MAX_RULES_PER_POLICY {
            return Err(PolicyError::TooManyRules {
                max: MAX_RULES_PER_POLICY,
                attempted: self.rules.len() + 1,
            });
        }

        self.rules.push(rule);
        Ok(self)
    }

    /// Add metadata to this policy
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Check if a peer is allowed to perform an action on a resource
    ///
    /// This method delegates to `PolicyAuthorizer` (SRP - Single Responsibility Principle).
    /// The Policy struct focuses on construction and management, while authorization
    /// logic is handled by the dedicated `PolicyAuthorizer`.
    #[must_use]
    pub fn is_allowed(&self, peer_id: &str, action: &Action, resource: &Resource) -> bool {
        crate::authorizer::PolicyAuthorizer::new(&self.rules).is_allowed(peer_id, action, resource)
    }

    /// Validate policy (check for conflicts, invalid rules, etc.)
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidRule` if:
    /// - Policy name is empty
    /// - Policy has no rules
    /// - Any rule has an empty peer ID
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(PolicyError::InvalidRule(
                "Policy name cannot be empty".to_string(),
            ));
        }

        if self.rules.is_empty() {
            return Err(PolicyError::InvalidRule(
                "Policy must have at least one rule".to_string(),
            ));
        }

        for rule in &self.rules {
            if rule.peer_id.is_empty() {
                return Err(PolicyError::InvalidRule(
                    "Peer ID cannot be empty".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Load policy from TOML string
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TOML parsing fails
    /// - Validation fails (see `validate()`)
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let policy: Self = toml::from_str(toml_str)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Serialize policy to TOML string
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::SerializationError` if TOML serialization fails
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| PolicyError::SerializationError(e.to_string()))
    }
}
