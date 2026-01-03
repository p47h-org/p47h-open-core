//! Authorization evaluation logic (SRP - Single Responsibility Principle)
//!
//! This module extracts the authorization logic from the `Policy` God Object,
//! providing a focused, testable component for evaluating access control rules.
//!
//! ## Architecture
//!
//! - **SRP**: Only responsible for authorization evaluation
//! - **Testable**: Can be tested independently without Policy overhead
//! - **Reusable**: Can be used with different rule sources

use crate::policy::{Action, PolicyRule, Resource};
use alloc::collections::BTreeMap;
use alloc::string::String;

/// Evaluates authorization rules (SRP - extracted from Policy)
///
/// This struct is responsible **only** for evaluating whether a given
/// peer/action/resource combination is allowed by a set of rules.
///
/// It does NOT handle:
/// - Policy construction
/// - Policy validation
/// - Policy serialization
/// - Rule management
///
/// ## Example
///
/// ```
/// use core_policy::{PolicyRule, Action, Resource};
/// use core_policy::authorizer::PolicyAuthorizer;
///
/// let rules = vec![
///     PolicyRule::new("alice".to_string(), Action::Read, Resource::All),
/// ];
///
/// let authorizer = PolicyAuthorizer::new(&rules);
/// assert!(authorizer.is_allowed("alice", &Action::Read, &Resource::File("/docs/file.txt".into())));
/// assert!(!authorizer.is_allowed("bob", &Action::Read, &Resource::File("/docs/file.txt".into())));
/// ```
#[derive(Debug)]
pub struct PolicyAuthorizer<'a> {
    rules: &'a [PolicyRule],
}

impl<'a> PolicyAuthorizer<'a> {
    /// Create a new authorizer with the given rules
    #[must_use]
    pub const fn new(rules: &'a [PolicyRule]) -> Self {
        Self { rules }
    }

    /// Check if a peer is allowed to perform an action on a resource (RBAC)
    ///
    /// This performs basic Role-Based Access Control checking without
    /// time or context validation.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer attempting the action
    /// * `action` - The action to perform
    /// * `resource` - The resource to access
    ///
    /// # Returns
    ///
    /// `true` if at least one rule allows the access, `false` otherwise
    #[must_use]
    pub fn is_allowed(&self, peer_id: &str, action: &Action, resource: &Resource) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.allows(peer_id, action, resource))
    }

    /// Check if a peer is allowed with full ABAC validation
    ///
    /// This performs Attribute-Based Access Control checking including:
    /// - Basic RBAC (peer/action/resource)
    /// - Time-based validation (expiration)
    /// - Context attributes validation
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer attempting the action
    /// * `action` - The action to perform
    /// * `resource` - The resource to access
    /// * `current_time` - Current Unix timestamp for expiration checks
    /// * `context` - Context attributes for ABAC
    ///
    /// # Returns
    ///
    /// `true` if at least one rule allows the access with valid time and context, `false` otherwise
    #[must_use]
    pub fn is_allowed_with_context(
        &self,
        peer_id: &str,
        action: &Action,
        resource: &Resource,
        current_time: u64,
        context: &BTreeMap<String, String>,
    ) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.allows_with_context(peer_id, action, resource, current_time, context))
    }

    /// Get all rules that allow a specific peer/action/resource combination
    ///
    /// Useful for auditing and debugging authorization decisions.
    ///
    /// # Returns
    ///
    /// An iterator over all matching rules
    pub fn matching_rules(
        &'a self,
        peer_id: &'a str,
        action: &'a Action,
        resource: &'a Resource,
    ) -> impl Iterator<Item = &'a PolicyRule> + 'a {
        self.rules
            .iter()
            .filter(move |rule| rule.allows(peer_id, action, resource))
    }

    /// Get the number of rules being evaluated
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Trait for types that can provide authorization (DIP - Dependency Inversion)
///
/// This trait allows different authorization implementations to be used
/// interchangeably. Clients depend on this abstraction, not concrete types.
pub trait Authorizer {
    /// Check if access is allowed
    fn is_allowed(&self, peer_id: &str, action: &Action, resource: &Resource) -> bool;
}

impl<'a> Authorizer for PolicyAuthorizer<'a> {
    fn is_allowed(&self, peer_id: &str, action: &Action, resource: &Resource) -> bool {
        PolicyAuthorizer::is_allowed(self, peer_id, action, resource)
    }
}
