use core_identity::Identity;
use core_policy::{Action, Policy, PolicyRule, Resource};
use wasm_bindgen::prelude::*;

/// WASM wrapper for Identity
#[wasm_bindgen]
pub struct WasmIdentity {
    inner: Identity,
}

#[wasm_bindgen]
impl WasmIdentity {
    /// Generate a new identity
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmIdentity, JsValue> {
        let mut rng = rand::thread_rng();
        let identity = Identity::generate(&mut rng)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate identity: {}", e)))?;

        Ok(WasmIdentity { inner: identity })
    }

    /// Get the public key hash as hex string
    #[wasm_bindgen(js_name = publicKeyHash)]
    pub fn public_key_hash(&self) -> String {
        hex::encode(self.inner.public_key_hash())
    }

    /// Get the DID (Decentralized Identifier)
    #[wasm_bindgen(js_name = getDid)]
    pub fn get_did(&self) -> String {
        format!("did:p47h:{}", self.public_key_hash())
    }
}

/// WASM wrapper for Policy
#[wasm_bindgen]
pub struct WasmPolicy {
    inner: Policy,
}

#[wasm_bindgen]
impl WasmPolicy {
    /// Create a new policy
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str, ttl_seconds: u64) -> Result<WasmPolicy, JsValue> {
        // Use 0 as timestamp for WASM compatibility
        // In production, timestamp should be provided by the server or JS Date.now()
        let now = 0;

        let policy = Policy::new(name, ttl_seconds, now)
            .map_err(|e| JsValue::from_str(&format!("Failed to create policy: {}", e)))?;

        Ok(WasmPolicy { inner: policy })
    }

    /// Add a rule to the policy
    #[wasm_bindgen(js_name = addRule)]
    pub fn add_rule(&mut self, peer_id: &str, action: &str, resource: &str) -> Result<(), JsValue> {
        let action = match action {
            "read" => Action::Read,
            "write" => Action::Write,
            "execute" => Action::Execute,
            "all" => Action::All,
            _ => return Err(JsValue::from_str(&format!("Invalid action: {}", action))),
        };

        let resource = if resource == "*" {
            Resource::All
        } else {
            // Simple resource parsing for wrapper
            Resource::File(resource.to_string())
        };

        let rule = PolicyRule::new(peer_id.to_string(), action, resource);

        // Since Policy fields are private, we need to rebuild the policy with the new rule
        // Get current policy data
        let current_name = self.inner.name().to_string();
        let current_issued_at = self.inner.issued_at();
        let current_valid_until = self.inner.valid_until();
        let ttl = current_valid_until.saturating_sub(current_issued_at);

        // Collect existing rules and add the new one
        let mut all_rules = self.inner.rules().to_vec();
        all_rules.push(rule);

        // Rebuild policy from scratch
        let mut new_policy = Policy::new(current_name, ttl, current_issued_at)
            .map_err(|e| JsValue::from_str(&format!("Failed to create policy: {}", e)))?;

        // Add all rules
        for r in all_rules {
            new_policy = new_policy
                .add_rule(r)
                .map_err(|e| JsValue::from_str(&format!("Failed to add rule: {}", e)))?;
        }

        // Copy metadata
        for (k, v) in self.inner.metadata() {
            new_policy = new_policy.with_metadata(k.clone(), v.clone());
        }

        self.inner = new_policy;

        Ok(())
    }

    /// Get policy name
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    /// Get number of rules
    #[wasm_bindgen(js_name = ruleCount)]
    pub fn rule_count(&self) -> usize {
        self.inner.rules().len()
    }

    /// Get the Merkle root hash of the policy
    ///
    /// Calculates the hash of the canonical TOML representation of the policy.
    /// This serves as the Merkle root for synchronization verification.
    #[wasm_bindgen(js_name = getRootHash)]
    pub fn get_root_hash(&self) -> Result<String, JsValue> {
        let toml = self
            .inner
            .to_toml()
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize policy: {}", e)))?;

        let digest = core_identity::hash::hash(toml.as_bytes());
        Ok(hex::encode(digest))
    }
}

impl WasmPolicy {
    /// Internal access to the inner policy
    pub fn get_inner(&self) -> &Policy {
        &self.inner
    }
}
