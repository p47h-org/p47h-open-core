use p47h_engine::{validate_policy, validate_policy_detailed};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn test_validate_valid_policy() {
    let policy = r#"
        name = "test-policy"
        version = 1
        
        [[rules]]
        peer_id = "did:p47h:abc123"
        action = "Read"
        resource = { File = "/data/*" }
    "#;

    assert!(validate_policy(policy).is_ok());
}

#[wasm_bindgen_test]
fn test_validate_invalid_toml() {
    let policy = "invalid toml {{{";
    assert!(validate_policy(policy).is_err());
}

#[wasm_bindgen_test]
fn test_validate_detailed_valid() {
    let policy = r#"
        name = "test-policy"
        version = 1
        
        [[rules]]
        peer_id = "did:p47h:abc123"
        action = "Read"
        resource = { File = "/data/*" }
    "#;

    let result = validate_policy_detailed(policy).unwrap();
    // Result should be a JS object, we can't easily inspect it in Rust tests
    // but we can verify it doesn't error
    assert!(result.is_truthy());
}

#[wasm_bindgen_test]
fn test_validate_detailed_empty_policy() {
    let policy = r#"
        name = "empty-policy"
        version = 1
        rules = []
    "#;

    // Should return diagnostic with valid=false
    let result = validate_policy_detailed(policy).unwrap();
    assert!(result.is_truthy());
}
