use alloc::string::String;
use core::fmt;

/// Specific errors for cryptographic identity operations
#[derive(Debug)]
pub enum IdentityError {
    #[allow(dead_code)]
    Generation(String),

    InvalidSignature,

    InvalidPublicKey,

    #[allow(dead_code)]
    InvalidKey(String),

    InvalidState(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generation(msg) => write!(f, "Error generating identity: {msg}"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidKey(msg) => write!(f, "Invalid key: {msg}"),
            Self::InvalidState(msg) => write!(f, "Invalid state: {msg}"),
        }
    }
}

impl core::error::Error for IdentityError {}

/// Specific Result type for identity operations
pub type Result<T> = core::result::Result<T, IdentityError>;
