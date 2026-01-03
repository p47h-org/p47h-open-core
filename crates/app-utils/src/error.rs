use std::time::SystemTimeError;
use thiserror::Error;

/// Errores principales para el crate `app-utils`.
#[derive(Error, Debug)]
pub enum Error {
    /// Error de tiempo del sistema
    #[error("System time error: {0}")]
    SystemTime(#[from] SystemTimeError),

    /// Error de decodificación Hex (Manual implementation)
    #[error("Hex decoding error: {0}")]
    Hex(String),

    /// Fallo al parsear YAML
    #[error("YAML parsing failed: {0}")]
    YamlParseError(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;
