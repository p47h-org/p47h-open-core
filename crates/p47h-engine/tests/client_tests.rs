use p47h_engine::P47hClient;
use wasm_bindgen_test::*;

/// Test-only session key - DO NOT use in production code
const TEST_SESSION_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

#[wasm_bindgen_test]
fn test_client_generation() {
    let client = P47hClient::generate_new().unwrap();
    let did = client.get_did();
    assert!(did.starts_with("did:p47h:"));
    assert_eq!(did.len(), 73); // "did:p47h:" + 64 hex chars
}

#[wasm_bindgen_test]
fn test_client_sign_challenge() {
    let client = P47hClient::generate_new().unwrap();
    let challenge = b"test_challenge_data";
    let signature = client.sign_challenge(challenge);
    assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes
}

#[wasm_bindgen_test]
fn test_client_roundtrip_via_wrapped_secret() {
    let client1 = P47hClient::generate_new().unwrap();
    let session_key = TEST_SESSION_KEY; // 32 bytes

    // Export wrapped
    let wrapped = client1.export_wrapped_secret(session_key).unwrap();

    // Import and verify identity is the same
    let client2 = P47hClient::from_wrapped_secret(&wrapped, session_key).unwrap();
    assert_eq!(client1.get_did(), client2.get_did());
}

#[wasm_bindgen_test]
fn test_client_public_key() {
    let client = P47hClient::generate_new().unwrap();
    let pub_key = client.get_public_key();
    assert_eq!(pub_key.len(), 32); // Ed25519 public key is 32 bytes
}

// ========== ENCRYPTED SECRET EXPORT TESTS ==========

#[wasm_bindgen_test]
fn test_wrapped_secret_export_import() {
    let client1 = P47hClient::generate_new().unwrap();
    let session_key = TEST_SESSION_KEY; // 32 bytes

    // Export wrapped
    let wrapped = client1.export_wrapped_secret(session_key).unwrap();

    // Verify format: nonce(12) + ciphertext + tag(16)
    assert!(wrapped.len() >= 12 + 32 + 16, "Wrapped secret too short");

    // Import and verify identity is the same
    let client2 = P47hClient::from_wrapped_secret(&wrapped, session_key).unwrap();
    assert_eq!(client1.get_did(), client2.get_did());
}

#[wasm_bindgen_test]
fn test_wrapped_secret_wrong_key_fails() {
    let client1 = P47hClient::generate_new().unwrap();
    let session_key = TEST_SESSION_KEY;
    let wrong_key = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    let wrapped = client1.export_wrapped_secret(session_key).unwrap();

    // Should fail with wrong key
    let result = P47hClient::from_wrapped_secret(&wrapped, wrong_key);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_wrapped_secret_invalid_key_length() {
    let client = P47hClient::generate_new().unwrap();
    let short_key = b"short";

    let result = client.export_wrapped_secret(short_key);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_wrapped_secret_corrupted_data_fails() {
    let client1 = P47hClient::generate_new().unwrap();
    let session_key = TEST_SESSION_KEY;

    let mut wrapped = client1.export_wrapped_secret(session_key).unwrap();

    // Corrupt the ciphertext
    if wrapped.len() > 20 {
        wrapped[20] ^= 0xFF;
    }

    // Should fail
    let result = P47hClient::from_wrapped_secret(&wrapped, session_key);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_wrapped_secret_different_every_time() {
    let client = P47hClient::generate_new().unwrap();
    let session_key = TEST_SESSION_KEY;

    // Export twice with same key
    let wrapped1 = client.export_wrapped_secret(session_key).unwrap();
    let wrapped2 = client.export_wrapped_secret(session_key).unwrap();

    // Should be different (different nonces)
    assert_ne!(
        wrapped1, wrapped2,
        "Wrapped secrets should differ due to random nonce"
    );
}

#[wasm_bindgen_test]
fn test_wrapped_secret_too_short() {
    let session_key = TEST_SESSION_KEY;
    let short_data = b"too_short";

    let result = P47hClient::from_wrapped_secret(short_data, session_key);
    assert!(result.is_err());
}
