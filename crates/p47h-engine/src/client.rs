use crate::types::AuthDecision;
use crate::utils::parse_resource;
use core_identity::Identity;
use core_policy::{Action, Policy};
use secrecy::ExposeSecret;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

/// WASM-compatible client managing Identity lifecycle and local policy evaluation.
///
/// Handles key generation, secure wrapped export (ChaCha20Poly1305), and signing
/// operations. Private keys remain within WASM linear memory unless explicitly exported.
#[wasm_bindgen]
pub struct P47hClient {
    /// Cryptographic identity (Ed25519 keypair)
    /// Private - never exposed directly to JavaScript
    identity: Identity,
}

#[wasm_bindgen]
impl P47hClient {
    // ========================================
    // AUTHENTICATION (Identity Management)
    // ========================================

    /// Generates a new cryptographic identity using browser's secure random source
    #[wasm_bindgen(constructor)]
    pub fn generate_new() -> Result<P47hClient, JsValue> {
        let mut rng = rand::thread_rng();
        let identity = Identity::generate(&mut rng)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate identity: {}", e)))?;

        Ok(P47hClient { identity })
    }

    /// Reconstructs identity from previously exported secret bytes
    #[wasm_bindgen]
    pub fn from_secret(secret_bytes: &[u8]) -> Result<P47hClient, JsValue> {
        if secret_bytes.len() != 32 {
            return Err(JsValue::from_str("Secret must be exactly 32 bytes"));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(secret_bytes);

        let identity = Identity::from_bytes(&key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to import identity: {}", e)))?;

        Ok(P47hClient { identity })
    }

    /// Exports the private key encrypted with ChaCha20Poly1305
    ///
    /// # Security
    ///
    /// This method encrypts the private key using ChaCha20Poly1305 AEAD cipher
    /// before exporting it. The caller must provide a 32-byte session key.
    ///
    /// # Arguments
    ///
    /// * `session_key` - A 32-byte key derived from user password or other secure source
    ///
    /// # Returns
    ///
    /// Returns a byte array containing: [nonce(12 bytes) || ciphertext || tag(16 bytes)]
    ///
    /// # Example
    ///
    /// ```javascript
    /// // Derive session key from password using PBKDF2 or similar
    /// const sessionKey = await deriveKey(password);
    /// const wrapped = client.export_wrapped_secret(sessionKey);
    /// // Store wrapped securely in IndexedDB
    /// ```
    #[wasm_bindgen]
    pub fn export_wrapped_secret(&self, session_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        if session_key.len() != 32 {
            return Err(JsValue::from_str("Session key must be exactly 32 bytes"));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(session_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid session key: {}", e)))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the private key
        let signing_key = self.identity.signing_key_bytes();
        let secret = signing_key.expose_secret();
        let ciphertext = cipher
            .encrypt(nonce, secret.as_ref())
            .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

        // Return [nonce || ciphertext]
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Imports identity from encrypted secret
    ///
    /// # Arguments
    ///
    /// * `wrapped` - The encrypted secret from `export_wrapped_secret`
    /// * `session_key` - The same 32-byte key used for encryption
    ///
    /// # Returns
    ///
    /// Returns a new `P47hClient` instance with the decrypted identity
    ///
    /// # Example
    ///
    /// ```javascript
    /// const sessionKey = await deriveKey(password);
    /// const client = P47hClient.from_wrapped_secret(wrapped, sessionKey);
    /// ```
    #[wasm_bindgen]
    pub fn from_wrapped_secret(wrapped: &[u8], session_key: &[u8]) -> Result<P47hClient, JsValue> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        if wrapped.len() < 12 + 32 + 16 {
            return Err(JsValue::from_str(
                "Invalid wrapped secret: too short (expected at least 60 bytes)",
            ));
        }

        if session_key.len() != 32 {
            return Err(JsValue::from_str("Session key must be exactly 32 bytes"));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(session_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid session key: {}", e)))?;

        let nonce = Nonce::from_slice(&wrapped[..12]);
        let ciphertext = &wrapped[12..];

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            JsValue::from_str("Decryption failed: wrong password or corrupted data")
        })?;

        Self::from_secret(&plaintext)
    }

    /// Returns the Decentralized Identifier (DID) for this identity
    #[wasm_bindgen]
    pub fn get_did(&self) -> String {
        let verifying_key = self.identity.verifying_key();
        let pub_key_bytes = verifying_key.as_bytes();
        format!("did:p47h:{}", hex::encode(pub_key_bytes))
    }

    /// Returns the raw public key bytes (for advanced use cases)
    #[wasm_bindgen]
    pub fn get_public_key(&self) -> Vec<u8> {
        self.identity.verifying_key().as_bytes().to_vec()
    }

    /// Signs a challenge for authentication with the server
    #[wasm_bindgen]
    pub fn sign_challenge(&self, challenge: &[u8]) -> Vec<u8> {
        self.identity.sign(challenge).to_bytes().to_vec()
    }

    /// Signs arbitrary data (for advanced use cases)
    #[wasm_bindgen]
    pub fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        self.identity.sign(data).to_bytes().to_vec()
    }

    // ========================================
    // AUTHORIZATION (Policy Evaluation)
    // ========================================

    /// Evaluates a policy request locally without server round-trip
    #[wasm_bindgen]
    pub fn evaluate_request(
        &self,
        policy_toml: &str,
        resource: &str,
        action: &str,
    ) -> Result<JsValue, JsValue> {
        let start = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now())
            .unwrap_or(0.0);

        // Parse policy from TOML
        let policy: Policy = toml::from_str(policy_toml)
            .map_err(|e| JsValue::from_str(&format!("Invalid policy TOML: {}", e)))?;

        // Get our DID as the principal
        let did = self.get_did();

        // Convert string action to Action enum
        let action_enum = match action.to_lowercase().as_str() {
            "read" => Action::Read,
            "write" => Action::Write,
            "execute" => Action::Execute,
            "delete" => Action::Delete,
            "all" | "*" => Action::All,
            custom => Action::Custom(custom.to_string()),
        };

        // Convert string resource to Resource enum
        let resource_enum = parse_resource(resource);

        // Evaluate policy
        let allowed = policy.is_allowed(&did, &action_enum, &resource_enum);

        let end = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now())
            .unwrap_or(0.0);

        // Convert milliseconds to microseconds (f64 -> u64)
        // performance.now() returns milliseconds, multiply by 1000 for microseconds
        let evaluation_time_us = ((end - start) * 1000.0) as u64;

        // Build detailed reasons
        let reasons = if allowed {
            vec![format!(
                "ALLOWED: {} access to {} granted by policy",
                action, resource
            )]
        } else {
            vec![format!(
                "DENIED: {} access to {} denied by policy",
                action, resource
            )]
        };

        let decision = AuthDecision {
            allowed,
            reasons,
            evaluation_time_us,
        };

        serde_wasm_bindgen::to_value(&decision)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Batch evaluation of multiple requests (more efficient)
    #[wasm_bindgen]
    pub fn evaluate_batch(
        &self,
        policy_toml: &str,
        requests_json: &str,
    ) -> Result<JsValue, JsValue> {
        #[derive(Deserialize)]
        struct BatchRequest {
            resource: String,
            action: String,
        }

        let start = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now())
            .unwrap_or(0.0);

        // Parse policy once
        let policy: Policy = toml::from_str(policy_toml)
            .map_err(|e| JsValue::from_str(&format!("Invalid policy TOML: {}", e)))?;

        // Parse requests
        let requests: Vec<BatchRequest> = serde_json::from_str(requests_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid requests JSON: {}", e)))?;

        let did = self.get_did();
        let mut decisions = Vec::with_capacity(requests.len());

        // Evaluate each request
        for req in requests {
            let action_enum = match req.action.to_lowercase().as_str() {
                "read" => Action::Read,
                "write" => Action::Write,
                "execute" => Action::Execute,
                "delete" => Action::Delete,
                "all" | "*" => Action::All,
                custom => Action::Custom(custom.to_string()),
            };

            let resource_enum = parse_resource(&req.resource);
            let allowed = policy.is_allowed(&did, &action_enum, &resource_enum);

            let reasons = if allowed {
                vec![format!(
                    "ALLOWED: {} access to {} granted",
                    req.action, req.resource
                )]
            } else {
                vec![format!(
                    "DENIED: {} access to {} denied",
                    req.action, req.resource
                )]
            };

            decisions.push(AuthDecision {
                allowed,
                reasons,
                evaluation_time_us: 0, // Individual timing not tracked in batch
            });
        }

        let end = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now())
            .unwrap_or(0.0);

        // Convert milliseconds to microseconds (f64 -> u64)
        let total_time_us = ((end - start) * 1000.0) as u64;

        // Add total time to last decision
        if let Some(last) = decisions.last_mut() {
            last.evaluation_time_us = total_time_us;
        }

        serde_wasm_bindgen::to_value(&decisions)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}
