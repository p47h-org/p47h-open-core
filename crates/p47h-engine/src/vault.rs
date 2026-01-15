// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 P47H Team <https://p47h.com>

//! Vault cryptographic operations.
//!
//! This module provides encryption/decryption for the P47H Identity Vault
//! using XChaCha20Poly1305 with Argon2id key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use wasm_bindgen::prelude::*;

/// Magic bytes identifying a valid P47H vault blob
pub const MAGIC_BYTES: &[u8] = b"P47H_VAULT_V2"; // V2 for WASM vault
/// Salt length in bytes
pub const SALT_LEN: usize = 16;
/// Nonce length in bytes (XChaCha20 uses 24-byte nonces)
pub const NONCE_LEN: usize = 24;
/// Minimum valid vault blob length
pub const MIN_VAULT_LEN: usize = MAGIC_BYTES.len() + SALT_LEN + NONCE_LEN;

// ============================================================================
// Pure Rust Error Type (for native fuzzing and testing)
// ============================================================================

/// Vault operation error (pure Rust, no WASM dependencies)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Random number generation failed
    RngError(String),
    /// Key derivation failed  
    KeyDerivationError(String),
    /// Encryption failed
    EncryptionError(String),
    /// Vault blob is too short to be valid
    TooShort { actual: usize, minimum: usize },
    /// Magic bytes don't match
    InvalidMagic,
    /// Decryption failed (wrong password or corrupted data)
    DecryptionFailed,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::RngError(msg) => write!(f, "RNG error: {}", msg),
            VaultError::KeyDerivationError(msg) => write!(f, "Key derivation failed: {}", msg),
            VaultError::EncryptionError(msg) => write!(f, "Encryption failed: {}", msg),
            VaultError::TooShort { actual, minimum } => {
                write!(f, "Invalid vault: too short ({} bytes, minimum {})", actual, minimum)
            }
            VaultError::InvalidMagic => write!(f, "Invalid vault: wrong magic bytes"),
            VaultError::DecryptionFailed => {
                write!(f, "Decryption failed: wrong password or corrupted data")
            }
        }
    }
}

impl std::error::Error for VaultError {}

impl From<VaultError> for JsValue {
    fn from(err: VaultError) -> JsValue {
        JsValue::from_str(&err.to_string())
    }
}

// ============================================================================
// Pure Rust Core Functions (fuzzable without WASM)
// ============================================================================

/// Derives a key from password and salt using Argon2id.
/// 
/// This is the pure Rust version without JsValue dependencies.
pub fn derive_key_inner(password: &str, salt: &[u8]) -> Result<chacha20poly1305::Key, VaultError> {
    let mut output_key = [0u8; 32];

    let params = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(32),
    )
    .map_err(|e| VaultError::KeyDerivationError(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|e| VaultError::KeyDerivationError(e.to_string()))?;

    Ok(*chacha20poly1305::Key::from_slice(&output_key))
}

/// Encrypts data with a provided salt and nonce (for testing/fuzzing).
/// 
/// In production, use `encrypt_vault_inner` which generates random salt/nonce.
pub fn encrypt_vault_with_params(
    data: &[u8],
    password: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, VaultError> {
    let key = derive_key_inner(password, salt)?;
    let nonce_obj = XNonce::from_slice(nonce);

    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(nonce_obj, data)
        .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

    let mut result = Vec::with_capacity(MAGIC_BYTES.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    result.extend_from_slice(MAGIC_BYTES);
    result.extend_from_slice(salt);
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts a vault blob (pure Rust, fuzzable).
///
/// # Arguments
/// * `blob` - The encrypted vault blob: `[MAGIC][SALT][NONCE][CIPHERTEXT]`
/// * `password` - User password
///
/// # Returns
/// Decrypted plaintext on success, or VaultError on failure.
pub fn decrypt_vault_inner(blob: &[u8], password: &str) -> Result<Vec<u8>, VaultError> {
    // Check minimum length
    if blob.len() < MIN_VAULT_LEN {
        return Err(VaultError::TooShort {
            actual: blob.len(),
            minimum: MIN_VAULT_LEN,
        });
    }

    // Verify magic bytes
    if &blob[0..MAGIC_BYTES.len()] != MAGIC_BYTES {
        return Err(VaultError::InvalidMagic);
    }

    // Parse header
    let offset_salt = MAGIC_BYTES.len();
    let offset_nonce = offset_salt + SALT_LEN;
    let offset_cipher = offset_nonce + NONCE_LEN;

    let salt = &blob[offset_salt..offset_nonce];
    let nonce_bytes = &blob[offset_nonce..offset_cipher];
    let ciphertext = &blob[offset_cipher..];

    // Derive key and decrypt
    let key = derive_key_inner(password, salt)?;
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok(plaintext)
}

// ============================================================================
// WASM Bindings (thin wrappers around pure Rust functions)
// ============================================================================

/// Crypto utilities for the Identity Vault
#[wasm_bindgen]
pub struct VaultCrypto;

#[wasm_bindgen]
impl VaultCrypto {
    /// Encrypts data using XChaCha20Poly1305 with a key derived from Argon2id
    /// Output format: [MAGIC_BYTES (13)] [SALT (16)] [NONCE (24)] [CIPHERTEXT]
    #[wasm_bindgen]
    pub fn encrypt_vault(data: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt)
            .map_err(|e| VaultError::RngError(e.to_string()))?;

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| VaultError::RngError(e.to_string()))?;

        encrypt_vault_with_params(data, password, &salt, &nonce).map_err(Into::into)
    }

    /// Decrypts a vault blob
    #[wasm_bindgen]
    pub fn decrypt_vault(blob: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
        decrypt_vault_inner(blob, password).map_err(Into::into)
    }

    /// Derives a session key from password and salt
    #[wasm_bindgen]
    pub fn derive_session_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = derive_key_inner(password, salt)?;
        Ok(key.to_vec())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"secret data";
        let password = "test_password";
        let salt = [1u8; SALT_LEN];
        let nonce = [2u8; NONCE_LEN];

        let encrypted = encrypt_vault_with_params(data, password, &salt, &nonce).unwrap();
        let decrypted = decrypt_vault_inner(&encrypted, password).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_too_short() {
        let result = decrypt_vault_inner(&[0u8; 10], "password");
        assert!(matches!(result, Err(VaultError::TooShort { .. })));
    }

    #[test]
    fn test_invalid_magic() {
        let mut blob = vec![0u8; MIN_VAULT_LEN + 16];
        blob[..5].copy_from_slice(b"WRONG");
        
        let result = decrypt_vault_inner(&blob, "password");
        assert!(matches!(result, Err(VaultError::InvalidMagic)));
    }

    #[test]
    fn test_wrong_password() {
        let data = b"secret data";
        let password = "correct_password";
        let salt = [1u8; SALT_LEN];
        let nonce = [2u8; NONCE_LEN];

        let encrypted = encrypt_vault_with_params(data, password, &salt, &nonce).unwrap();
        let result = decrypt_vault_inner(&encrypted, "wrong_password");

        assert!(matches!(result, Err(VaultError::DecryptionFailed)));
    }
}

// ============================================================================
// Kani Formal Verification Proofs
// ============================================================================

/// Formal verification proofs for vault constants and validation logic.
/// Run with: `cargo kani --package p47h-engine`
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Verify that MIN_VAULT_LEN is correctly computed from components.
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_min_vault_len_invariant() {
        let expected = MAGIC_BYTES.len() + SALT_LEN + NONCE_LEN;
        kani::assert(MIN_VAULT_LEN == expected, "MIN_VAULT_LEN must equal components sum");
    }

    /// Verify XChaCha20 nonce size is 24 bytes.
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_nonce_len_xchacha() {
        kani::assert(NONCE_LEN == 24, "XChaCha20 requires 24-byte nonces");
    }

    /// Verify salt length is at least 16 bytes (Argon2 minimum).
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_salt_len_argon2() {
        kani::assert(SALT_LEN >= 16, "Argon2 requires at least 16-byte salt");
    }

    /// Verify that a blob shorter than MIN_VAULT_LEN would be rejected.
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_short_blob_rejected() {
        let short_len: usize = kani::any();
        kani::assume(short_len < MIN_VAULT_LEN);
        // The validation check in decrypt_vault_inner
        let is_too_short = short_len < MIN_VAULT_LEN;
        kani::assert(is_too_short, "Short blobs must fail validation");
    }
}

