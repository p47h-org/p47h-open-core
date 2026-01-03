//! # app-utils
//!
//! Utility modules for policy parsing and timestamps.
//!
//! This crate provides non-core features:
//! - YAML policy parsing
//! - Trusted timestamp management
//!
//! Shared utilities for policy parsing (YAML) and trusted timestamp validation.

#![forbid(unsafe_code)]

pub mod error;

pub mod yaml {
    //! YAML policy document parsing and serialization
    use core_policy::{Policy, PolicyError};
    use serde::{Deserialize, Serialize};

    /// Trait for policy parsers (OCP - extensible to JSON, TOML, etc.)
    pub trait PolicyParser {
        /// Parse a policy from a string
        fn parse(&self, input: &str) -> Result<Policy, PolicyError>;
    }

    /// YAML parser implementation
    pub struct YamlParser;

    impl PolicyParser for YamlParser {
        fn parse(&self, input: &str) -> Result<Policy, PolicyError> {
            let policy: Policy = serde_yaml::from_str(input)
                .map_err(|e| PolicyError::SerializationError(format!("YAML parse error: {}", e)))?;
            policy.validate()?;
            Ok(policy)
        }
    }

    /// Serialize a value to YAML
    pub fn to_yaml<T: Serialize>(value: &T) -> Result<String, String> {
        serde_yaml::to_string(value).map_err(|e| format!("YAML serialization error: {}", e))
    }

    /// Deserialize from YAML
    pub fn from_yaml<'a, T: Deserialize<'a>>(input: &'a str) -> Result<T, String> {
        serde_yaml::from_str(input).map_err(|e| format!("YAML deserialization error: {}", e))
    }
}

pub mod timestamp {
    //! Trusted timestamp authority integration

    use super::error::Result;
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Trusted timestamp from a timestamp authority
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TrustedTimestamp {
        /// Unix timestamp in seconds
        pub timestamp: u64,

        /// Timestamp authority identifier
        pub authority: String,

        /// Signature over the timestamp
        pub signature: Vec<u8>,
    }

    impl TrustedTimestamp {
        /// Create a new timestamp (unsigned - for testing)
        pub fn new(authority: String) -> Result<Self> {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            Ok(Self {
                timestamp,
                authority,
                signature: Vec::new(),
            })
        }

        /// Get the timestamp as SystemTime
        pub fn as_system_time(&self) -> SystemTime {
            UNIX_EPOCH + std::time::Duration::from_secs(self.timestamp)
        }

        /// Check if timestamp is within a certain age
        pub fn is_fresh(&self, max_age_secs: u64) -> Result<bool> {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            Ok(now.saturating_sub(self.timestamp) <= max_age_secs)
        }
    }

    /// Simple timestamp provider (system time)
    #[derive(Debug, Default)]
    pub struct SystemTimestampProvider {
        authority_id: String,
    }

    impl SystemTimestampProvider {
        /// Create a new provider
        pub fn new(authority_id: String) -> Self {
            Self { authority_id }
        }

        /// Get current timestamp
        pub fn now(&self) -> Result<TrustedTimestamp> {
            TrustedTimestamp::new(self.authority_id.clone())
        }
    }
}

/// Re-export `hex` crate for encoding/decoding utilities.
pub use hex;

/// Re-export commonly used types
pub use error::{Error, Result};
pub use yaml::{PolicyParser, YamlParser};
