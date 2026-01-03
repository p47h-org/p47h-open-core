use p47h_engine::{WasmIdentity, WasmPolicy};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn test_identity_creation() {
    let identity = WasmIdentity::new().unwrap();
    let did = identity.get_did();
    assert!(did.starts_with("did:p47h:"));
}

#[wasm_bindgen_test]
fn test_policy_creation() {
    let policy = WasmPolicy::new("test-policy", 3600).unwrap();
    assert_eq!(policy.name(), "test-policy");
    assert_eq!(policy.rule_count(), 0);
}

#[wasm_bindgen_test]
fn test_policy_add_rule() {
    let mut policy = WasmPolicy::new("test-policy", 3600).unwrap();
    policy.add_rule("peer1", "read", "/data").unwrap();
    assert_eq!(policy.rule_count(), 1);
}
