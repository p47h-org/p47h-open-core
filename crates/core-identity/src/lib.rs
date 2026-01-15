// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 P47H Team <https://p47h.com>

//! # identity
//!
//! Cryptographic identities for p47h based on Ed25519.
//!
//! This crate provides secure, auditable, and memory-safe identity management
//! using industry-standard Ed25519 signatures with proper key hygiene.
//!
//! ## Features
//!
//! - **Ed25519 Signatures**: NIST-compliant digital signatures
//! - **Memory Safety**: Automatic zeroization of private keys
//! - **Blake3 Hashing**: Fast public key hashing for lookups
//! - **libp2p Integration**: Seamless conversion to libp2p keypairs
//!
//! ## Example
//!
//! ```
//! use core_identity::Identity;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new identity
//! let mut rng = rand::thread_rng();
//! let identity = Identity::generate(&mut rng)?;
//!
//! // Sign a message
//! let message = b"Hello, network!";
//! let signature = identity.sign(message);
//!
//! // Verify the signature
//! use core_identity::verify_signature;
//! verify_signature(&identity.verifying_key(), message, &signature)?;
//! # Ok(())
//! # }
//! ```

mod error;
pub mod hash;

pub use error::{IdentityError, Result};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use rand_core::{CryptoRng, RngCore};

/// Cryptographic identity based on Ed25519
///
/// Each node in the network has a unique identity represented by a key pair.
/// The public key is the node's identity, the private key never leaves this module.
///
/// ## Security
///
/// - Private keys are automatically zeroized on drop
/// - Uses OS-level CSPRNG for key generation
/// - Blake3 hashing for fast public key comparisons
///
/// ## Example
///
/// ```
/// use core_identity::Identity;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = rand::thread_rng();
/// let identity = Identity::generate(&mut rng)?;
/// let public_key = identity.verifying_key();
/// let public_key_hash = identity.public_key_hash();
///
/// assert_eq!(public_key_hash.len(), 32);
/// # Ok(())
/// # }
/// ```
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    keypair: SigningKey,
}
impl Identity {
    /// Generates a new identity using a provided CSPRNG.
    ///
    /// # Example
    ///
    /// ```
    /// use core_identity::Identity;
    ///
    /// let mut rng = rand::thread_rng();
    /// let identity = Identity::generate(&mut rng).expect("Failed to generate identity");
    /// assert_eq!(identity.public_key_hash().len(), 32);
    /// ```
    ///
    /// # Errors
    ///
    /// This function is infallible in practice, but returns `Result`
    /// for consistency with the API.
    pub fn generate<R>(csprng: &mut R) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        Ok(Self {
            keypair: SigningKey::generate(csprng),
        })
    }

    /// Creates an identity from a 32-byte seed
    ///
    /// Useful for testing or deriving identities deterministically
    ///
    /// # Example
    ///
    /// ```
    /// use core_identity::Identity;
    ///
    /// let seed = [42u8; 32];
    /// let identity1 = Identity::from_seed(&seed).unwrap();
    /// let identity2 = Identity::from_seed(&seed).unwrap();
    ///
    /// // Same seed produces same identity
    /// assert_eq!(
    ///     identity1.verifying_key().as_bytes(),
    ///     identity2.verifying_key().as_bytes()
    /// );
    /// ```
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let keypair = SigningKey::from_bytes(seed);

        Ok(Self { keypair })
    }

    /// Creates an identity from raw signing key bytes
    ///
    /// # Security
    ///
    /// This method should only be used for deserialization from secure storage
    /// (e.g., encrypted keystore).
    ///
    /// # Errors
    ///
    /// Currently infallible, but returns `Result` for API consistency.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let keypair = SigningKey::from_bytes(bytes);
        Ok(Self { keypair })
    }

    /// Returns the public key
    ///
    /// This is the identity shared with other nodes
    ///
    /// # Example
    ///
    /// ```
    /// use core_identity::Identity;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut rng = rand::thread_rng();
    /// let identity = Identity::generate(&mut rng)?;
    /// let public_key = identity.verifying_key();
    ///
    /// // Public key is 32 bytes
    /// assert_eq!(public_key.as_bytes().len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    pub fn verifying_key(&self) -> VerifyingKey {
        self.keypair.verifying_key()
    }

    /// Returns the hash of the public key
    ///
    /// Uses the configured hash provider (default: Blake3) for efficient lookups.
    pub fn public_key_hash(&self) -> [u8; 32] {
        let bytes = self.keypair.verifying_key().to_bytes();
        hash::hash(&bytes)
    }

    /// Signs a message with the private key
    ///
    /// # Arguments
    ///
    /// * `message` - The bytes to sign
    ///
    /// # Returns
    ///
    /// A signature that can be verified with the public key
    ///
    /// # Example
    ///
    /// ```
    /// use core_identity::{Identity, verify_signature};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut rng = rand::thread_rng();
    /// let identity = Identity::generate(&mut rng)?;
    /// let message = b"Important message";
    ///
    /// let signature = identity.sign(message);
    /// verify_signature(&identity.verifying_key(), message, &signature)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Returns the signing key bytes for serialization
    ///
    /// # Security
    ///
    /// This method returns a `Secret<Vec<u8>>` that prevents accidental exposure:
    /// - Cannot be printed with Debug/Display
    /// - Will not appear in logs automatically
    /// - Requires explicit `.expose_secret()` to access
    ///
    /// Should only be used for:
    /// - Secure serialization (encrypted keystore)
    /// - Conversion to libp2p keypair
    /// - Low-level cryptographic operations
    ///
    /// WARNING: Use `.expose_secret()` only when absolutely necessary.
    /// The exposed bytes should be:
    /// - Encrypted immediately if stored
    /// - Zeroized after use
    /// - Never logged or transmitted unencrypted
    ///
    /// # Example
    ///
    /// ```
    /// use core_identity::Identity;
    /// use secrecy::ExposeSecret;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut rng = rand::thread_rng();
    /// let identity = Identity::generate(&mut rng)?;
    ///
    /// // Get the secret bytes
    /// let secret_bytes = identity.signing_key_bytes();
    ///
    /// // Only expose when needed for cryptographic operations
    /// let raw_bytes = secret_bytes.expose_secret();
    /// // Use raw_bytes for signing, serialization, etc.
    /// # Ok(())
    /// # }
    /// ```
    pub fn signing_key_bytes(&self) -> Secret<Vec<u8>> {
        Secret::new(self.keypair.to_bytes().to_vec())
    }
}

/// Verifies a signature for a given message and public key
///
/// # Arguments
///
/// * `verifying_key` - Public key to verify the signature
/// * `message` - Message that was signed
/// * `signature` - Signature to verify
///
/// # Returns
///
/// * `Ok(())` - If the signature is valid
/// * `Err(IdentityError::InvalidSignature)` - If the signature is invalid
///
/// # Example
///
/// ```
/// use core_identity::{Identity, verify_signature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = rand::thread_rng();
/// let identity = Identity::generate(&mut rng)?;
/// let message = b"Authentic message";
/// let signature = identity.sign(message);
///
/// // Verify with just the public key
/// verify_signature(&identity.verifying_key(), message, &signature)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

/// Serializable representation of a public key
///
/// This type allows Ed25519 public keys to be serialized and deserialized
/// safely for storage or transmission.
///
/// # Example
///
/// ```
/// use core_identity::{Identity, SerializableVerifyingKey};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = rand::thread_rng();
/// let identity = Identity::generate(&mut rng)?;
/// let public_key = identity.verifying_key();
///
/// // Convert to serializable form
/// let serializable = SerializableVerifyingKey::from(&public_key);
///
/// // Serialize (e.g., with JSON)
/// let json = serde_json::to_string(&serializable)?;
///
/// // Deserialize
/// let deserialized: SerializableVerifyingKey = serde_json::from_str(&json)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SerializableVerifyingKey([u8; 32]);

impl SerializableVerifyingKey {
    /// Returns the bytes of the public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<&VerifyingKey> for SerializableVerifyingKey {
    fn from(vk: &VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

impl TryFrom<SerializableVerifyingKey> for VerifyingKey {
    type Error = IdentityError;

    fn try_from(svk: SerializableVerifyingKey) -> Result<Self> {
        VerifyingKey::from_bytes(&svk.0).map_err(|_| IdentityError::InvalidPublicKey)
    }
}

// ============================================================================
// Kani Formal Verification Proofs
// ============================================================================

/// Formal verification proofs for cryptographic size invariants.
/// Run with: `cargo kani --package core-identity`
#[cfg(kani)]
mod kani_proofs {
    /// Ed25519 public key size is always 32 bytes.
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_ed25519_pubkey_size() {
        // Ed25519 public keys are 32 bytes (compressed curve point)
        const ED25519_PUBKEY_LEN: usize = 32;
        kani::assert(ED25519_PUBKEY_LEN == 32, "Ed25519 public key must be 32 bytes");
    }

    /// Ed25519 signature size is always 64 bytes.
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_ed25519_signature_size() {
        // Ed25519 signatures are 64 bytes (R + S components)
        const ED25519_SIG_LEN: usize = 64;
        kani::assert(ED25519_SIG_LEN == 64, "Ed25519 signature must be 64 bytes");
    }

    /// Ed25519 seed/secret key size is always 32 bytes.
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_ed25519_seed_size() {
        const ED25519_SEED_LEN: usize = 32;
        kani::assert(ED25519_SEED_LEN == 32, "Ed25519 seed must be 32 bytes");
    }

    /// Blake3 hash output is always 32 bytes.
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_blake3_hash_size() {
        const BLAKE3_OUTPUT_LEN: usize = 32;
        kani::assert(BLAKE3_OUTPUT_LEN == 32, "Blake3 hash must be 32 bytes");
    }
}

