use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use wasm_bindgen::prelude::*;

const MAGIC_BYTES: &[u8] = b"P47H_VAULT_V2"; // V2 for WASM vault
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

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
            .map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;

        let key = derive_key(password, &salt)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let cipher = XChaCha20Poly1305::new(&key);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

        let mut result =
            Vec::with_capacity(MAGIC_BYTES.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
        result.extend_from_slice(MAGIC_BYTES);
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypts a vault blob
    #[wasm_bindgen]
    pub fn decrypt_vault(blob: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
        if blob.len() < MAGIC_BYTES.len() + SALT_LEN + NONCE_LEN {
            return Err(JsValue::from_str("Invalid vault: too short"));
        }

        if &blob[0..MAGIC_BYTES.len()] != MAGIC_BYTES {
            return Err(JsValue::from_str("Invalid vault: wrong magic bytes"));
        }

        let offset_salt = MAGIC_BYTES.len();
        let offset_nonce = offset_salt + SALT_LEN;
        let offset_cipher = offset_nonce + NONCE_LEN;

        let salt = &blob[offset_salt..offset_nonce];
        let nonce_bytes = &blob[offset_nonce..offset_cipher];
        let ciphertext = &blob[offset_cipher..];

        let key = derive_key(password, salt)?;
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = XNonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            JsValue::from_str("Decryption failed: wrong password or corrupted data")
        })?;

        Ok(plaintext)
    }

    /// Derives a session key from password and salt
    #[wasm_bindgen]
    pub fn derive_session_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = derive_key(password, salt)?;
        Ok(key.to_vec())
    }
}

/// Argon2id key derivation with WASM-optimized parameters.
/// Memory: 19 MiB, Iterations: 2, Parallelism: 1
fn derive_key(password: &str, salt: &[u8]) -> Result<chacha20poly1305::Key, JsValue> {
    let mut output_key = [0u8; 32];

    let params = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(32),
    )
    .map_err(|e| JsValue::from_str(&format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {}", e)))?;

    Ok(*chacha20poly1305::Key::from_slice(&output_key))
}
