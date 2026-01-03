use anyhow::Result;
use argon2::{password_hash::rand_core::OsRng, password_hash::SaltString, Argon2};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct EncryptedIdentity {
    pub version: u8,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Encrypts data with a password using Argon2id for KDF and ChaCha20Poly1305 for encryption
pub fn encrypt(data: &[u8], password: &str) -> Result<EncryptedIdentity> {
    // 1. Generate Salt
    let salt = SaltString::generate(&mut OsRng);

    // 2. Derive Key using Argon2id with hardened parameters for long-term key storage
    // Parameters: m_cost=64MB, t_cost=3 iterations, p_cost=4 parallelism
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    // We use the salt to hash the password, the resulting hash includes the salt and params
    // But for raw key derivation we need a slightly different approach or just hash it and use the output bytes.
    // Simpler approach for file encryption: Use Argon2 to fill a 32-byte buffer (Key).

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(
            password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut key_bytes,
        )
        .map_err(|e| anyhow::anyhow!("KDF failed: {}", e))?;

    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // 3. Generate Nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 4. Encrypt
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Zeroize key immediately
    key_bytes.zeroize();

    Ok(EncryptedIdentity {
        version: 1,
        salt: salt.as_str().to_string(),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

// Note: Decryption would be implemented similarly when we add 'did load' or 'did export' commands.
