//! Hash provider abstraction for identity operations
//!
//! This module provides a trait-based abstraction for hashing operations,
//! allowing the core-identity crate to remain decoupled from specific
//! hash implementations.

use blake3;

/// Hash provider trait for identity operations
///
/// This trait abstracts the hashing algorithm used for identity operations,
/// following the Dependency Inversion Principle (DIP). The core identity
/// logic depends on this abstraction rather than concrete implementations.
///
/// ## Design Rationale
///
/// - **Decoupling**: Core identity logic doesn't depend on Blake3 directly
/// - **Testability**: Can use mock hash providers in tests
/// - **Flexibility**: Easy to switch hash algorithms if needed
/// - **Future-proofing**: Supports quantum-resistant hashes in the future
pub trait HashProvider {
    /// Hash arbitrary data to a 32-byte digest
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    ///
    /// # Returns
    ///
    /// A 32-byte hash digest
    fn hash(&self, data: &[u8]) -> [u8; 32];

    /// Get the name of this hash provider (for debugging/logging)
    fn name(&self) -> &'static str;
}

/// Default Blake3 hash provider
///
/// This is the default implementation using Blake3, a fast cryptographic
/// hash function. Blake3 provides:
///
/// - **Speed**: Faster than SHA-256, SHA-3, and BLAKE2
/// - **Security**: 256-bit security level
/// - **Simplicity**: Single-pass, no configuration needed
/// - **Parallelism**: Can leverage multiple cores
///
/// ## Example
///
/// ```
/// use core_identity::hash::{HashProvider, Blake3HashProvider};
///
/// let provider = Blake3HashProvider;
/// let hash = provider.hash(b"Hello, world!");
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3HashProvider;

impl HashProvider for Blake3HashProvider {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }

    fn name(&self) -> &'static str {
        "blake3"
    }
}

/// Global hash provider instance
///
/// This is the default hash provider used throughout the crate.
/// Currently set to Blake3, but can be changed in the future if needed.
static HASH_PROVIDER: Blake3HashProvider = Blake3HashProvider;

/// Get the current hash provider
///
/// Returns a reference to the global hash provider. This allows
/// the entire crate to use a consistent hashing algorithm.
///
/// ## Example
///
/// ```
/// use core_identity::hash::{hash_provider, HashProvider};
///
/// let provider = hash_provider();
/// let hash = provider.hash(b"data");
/// ```
pub fn hash_provider() -> &'static impl HashProvider {
    &HASH_PROVIDER
}

/// Convenience function for hashing data
///
/// This is a shorthand for `hash_provider().hash(data)`.
///
/// ## Example
///
/// ```
/// use core_identity::hash::hash;
///
/// let digest = hash(b"Hello, world!");
/// assert_eq!(digest.len(), 32);
/// ```
#[inline]
pub fn hash(data: &[u8]) -> [u8; 32] {
    hash_provider().hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_provider() {
        let provider = Blake3HashProvider;
        let hash1 = provider.hash(b"test");
        let hash2 = provider.hash(b"test");

        // Same input should produce same output
        assert_eq!(hash1, hash2);

        // Different input should produce different output
        let hash3 = provider.hash(b"different");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_function() {
        let hash1 = hash(b"test data");
        let hash2 = hash(b"test data");

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_provider_name() {
        let provider = Blake3HashProvider;
        assert_eq!(provider.name(), "blake3");
    }

    #[test]
    fn test_empty_input() {
        let hash = hash(b"");
        assert_eq!(hash.len(), 32);
        // Blake3 of empty string is a known value
        assert_ne!(hash, [0u8; 32]);
    }
}
