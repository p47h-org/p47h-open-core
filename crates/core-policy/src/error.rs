//! Error types for mesh-policy-core

use alloc::string::String;
use core::fmt;

/// Result type alias for policy operations
pub type Result<T> = core::result::Result<T, PolicyError>;

/// Errors that can occur in policy operations
#[derive(Debug)]
pub enum PolicyError {
    /// Policy not found
    PolicyNotFound(String),

    /// Invalid policy rule
    InvalidRule(String),

    /// Permission denied
    PermissionDenied {
        /// Peer ID that was denied
        peer_id: String,
        /// Reason for denial
        reason: String,
    },

    /// Invalid peer ID
    InvalidPeerId(String),

    /// Serialization error
    SerializationError(String),

    /// TOML parsing error
    TomlError(toml::de::Error),

    /// IO error
    // IoError removed for no_std

    // ===== DoS Prevention Errors (T20 mitigation) =====

    /// Policy exceeds maximum allowed rules (DoS prevention - T20)
    TooManyRules {
        /// Maximum allowed rules
        max: usize,
        /// Attempted number of rules
        attempted: usize,
    },

    /// Resource pattern exceeds maximum length (DoS prevention - T20)
    PatternTooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual pattern length
        length: usize,
    },

    /// Policy name exceeds maximum length (DoS prevention - T20)
    NameTooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual name length
        length: usize,
    },

    // ===== ABAC Expression Errors =====
    /// Context expression is too deeply nested (stack overflow prevention)
    ExpressionTooDeep {
        /// Maximum allowed depth
        max: usize,
    },

    /// Context expression string is too long (DoS prevention)
    ExpressionTooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual expression length
        length: usize,
    },

    /// Invalid expression syntax
    InvalidExpression(String),

    /// System time error (clock went backwards or unavailable)
    // TimeError removed for no_std

    /// Internal error
    InternalError(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyNotFound(msg) => write!(f, "Policy not found: {}", msg),
            Self::InvalidRule(msg) => write!(f, "Invalid policy rule: {}", msg),
            Self::PermissionDenied { peer_id, reason } => {
                write!(f, "Permission denied for peer {}: {}", peer_id, reason)
            }
            Self::InvalidPeerId(msg) => write!(f, "Invalid peer ID: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::TomlError(e) => write!(f, "TOML parsing error: {}", e),
            Self::TooManyRules { max, attempted } => write!(
                f,
                "Policy exceeds maximum {} rules (attempted: {})",
                max, attempted
            ),
            Self::PatternTooLong { max, length } => write!(
                f,
                "Resource pattern exceeds maximum {} characters (length: {})",
                max, length
            ),
            Self::NameTooLong { max, length } => write!(
                f,
                "Policy name exceeds maximum {} characters (length: {})",
                max, length
            ),
            Self::ExpressionTooDeep { max } => write!(
                f,
                "Context expression exceeds maximum depth of {} (prevents stack overflow)",
                max
            ),
            Self::ExpressionTooLong { max, length } => write!(
                f,
                "Context expression exceeds maximum {} characters (length: {})",
                max, length
            ),
            Self::InvalidExpression(msg) => write!(f, "Invalid context expression: {}", msg),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl From<toml::de::Error> for PolicyError {
    fn from(err: toml::de::Error) -> Self {
        Self::TomlError(err)
    }
}

impl core::error::Error for PolicyError {}
