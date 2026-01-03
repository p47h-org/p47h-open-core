// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 P47H Team <https://p47h.com>

//! # mesh-policy-core
//!
//! Pure RBAC/ABAC policy engine with zero dependencies on crypto or network layers.
//!
//! This crate provides the core domain logic for authorization policies, including:
//! - Policy rules and evaluation
//! - Resource path matching
//! - Role-Based Access Control (RBAC)
//! - Attribute-Based Access Control (ABAC)
//!
//! ## Security
//!
//! - **T20 Mitigation**: Strict limits on policy size to prevent algorithmic DoS
//!   - MAX_RULES_PER_POLICY = 1024
//!   - MAX_RESOURCE_PATTERN_LENGTH = 256

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod authorizer;
pub mod builder;
pub mod context_expr;
pub mod error;
pub mod path;
pub mod policy;
pub mod resource_matcher;

pub use authorizer::{Authorizer, PolicyAuthorizer};
pub use builder::{PolicyBuilder, PolicyRuleBuilder};
pub use context_expr::{CompareOp, ContextExpr, MAX_EXPR_DEPTH, MAX_EXPR_LENGTH};
/// Re-export commonly used types
pub use error::{PolicyError, Result};
pub use path::PathPattern;
pub use policy::{Action, Policy, PolicyRule, Resource};
pub use resource_matcher::{ResourceMatcher, ResourceMatcherRegistry};

/// Maximum number of rules per policy (T20 DoS mitigation)
pub const MAX_RULES_PER_POLICY: usize = 1024;

/// Maximum length for resource patterns (T20 DoS mitigation)
pub const MAX_RESOURCE_PATTERN_LENGTH: usize = 256;

/// Maximum length for policy name (T20 DoS mitigation)
pub const MAX_POLICY_NAME_LENGTH: usize = 128;
