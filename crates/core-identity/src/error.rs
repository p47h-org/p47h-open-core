use thiserror::Error;

/// Specific errors for cryptographic identity operations
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Error generating identity: {0}")]
    Generation(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}
/// Specific Result type for identity operations
pub type Result<T> = std::result::Result<T, IdentityError>;
