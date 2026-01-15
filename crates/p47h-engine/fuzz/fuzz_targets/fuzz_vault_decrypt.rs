//! Fuzz target for VaultCrypto::decrypt_vault
//!
//! This target bombards the vault decryption logic with malformed binary blobs
//! to find potential panics or crashes in header parsing.
//!
//! Attack vectors tested:
//! - Truncated blobs (too short)
//! - Wrong magic bytes
//! - Corrupted salt/nonce regions
//! - Random binary data

#![no_main]

use libfuzzer_sys::fuzz_target;
use p47h_engine::vault::{
    decrypt_vault_inner, VaultError, MAGIC_BYTES, MIN_VAULT_LEN, NONCE_LEN, SALT_LEN,
};

fuzz_target!(|data: &[u8]| {
    // Test with arbitrary binary data - should NEVER panic
    let password = "test_password";
    
    // Try to decrypt arbitrary data
    let result = decrypt_vault_inner(data, password);
    
    // Verify we get proper errors, not panics
    match result {
        Ok(_) => {
            // Decryption succeeded - this would be surprising with random data
            // but not impossible if the data happens to be valid
        }
        Err(VaultError::TooShort { actual, minimum }) => {
            // Expected for short inputs
            assert!(actual < minimum);
            assert_eq!(minimum, MIN_VAULT_LEN);
        }
        Err(VaultError::InvalidMagic) => {
            // Expected if magic bytes don't match
            // Verify the check was correct
            if data.len() >= MAGIC_BYTES.len() {
                assert_ne!(&data[..MAGIC_BYTES.len()], MAGIC_BYTES);
            }
        }
        Err(VaultError::DecryptionFailed) => {
            // Expected - wrong password or corrupted ciphertext
        }
        Err(VaultError::KeyDerivationError(_)) => {
            // Possible if Argon2 fails (e.g., invalid salt length)
        }
        Err(_) => {
            // Other errors are acceptable
        }
    }
});

/// Additional structured tests for specific attack patterns
#[cfg(test)]
mod tests {
    use super::*;
    use p47h_engine::vault::encrypt_vault_with_params;

    #[test]
    fn test_truncated_blobs() {
        let password = "test";
        
        // Test blobs of every length from 0 to MIN_VAULT_LEN + 10
        for len in 0..=MIN_VAULT_LEN + 10 {
            let blob = vec![0u8; len];
            let result = decrypt_vault_inner(&blob, password);
            
            // Short blobs should return TooShort, others InvalidMagic or DecryptionFailed
            if len < MIN_VAULT_LEN {
                assert!(matches!(result, Err(VaultError::TooShort { .. })));
            } else {
                // Has enough bytes but wrong magic
                assert!(matches!(result, Err(VaultError::InvalidMagic)));
            }
        }
    }

    #[test]
    fn test_valid_magic_corrupted_data() {
        let mut blob = vec![0u8; MIN_VAULT_LEN + 100];
        blob[..MAGIC_BYTES.len()].copy_from_slice(MAGIC_BYTES);
        
        let result = decrypt_vault_inner(&blob, "password");
        
        // Should fail with DecryptionFailed, not panic
        assert!(matches!(result, Err(VaultError::DecryptionFailed)));
    }

    #[test]
    fn test_bit_flip_attack() {
        // Create a valid encrypted blob
        let data = b"secret data";
        let password = "password";
        let salt = [1u8; SALT_LEN];
        let nonce = [2u8; NONCE_LEN];
        
        let encrypted = encrypt_vault_with_params(data, password, &salt, &nonce).unwrap();
        
        // Verify it decrypts correctly
        let decrypted = decrypt_vault_inner(&encrypted, password).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
        
        // Flip each bit and verify it fails gracefully
        for i in 0..encrypted.len() {
            for bit in 0..8 {
                let mut corrupted = encrypted.clone();
                corrupted[i] ^= 1 << bit;
                
                let result = decrypt_vault_inner(&corrupted, password);
                
                // Should fail with an error, never panic
                // The specific error depends on which byte was corrupted
                assert!(result.is_err());
            }
        }
    }
}
