use core_identity::{verify_signature, Identity};

#[test]
fn test_identity_generation() {
    let mut rng = rand::thread_rng();
    let identity = Identity::generate(&mut rng).expect("Failed to generate");
    assert_eq!(identity.verifying_key().as_bytes().len(), 32);
}

#[test]
fn test_identity_from_seed() {
    let seed = [42u8; 32];
    let identity1 = Identity::from_seed(&seed).unwrap();
    let identity2 = Identity::from_seed(&seed).unwrap();

    // Same seed should produce the same public key
    assert_eq!(
        identity1.verifying_key().as_bytes(),
        identity2.verifying_key().as_bytes()
    );
}

#[test]
fn test_sign_and_verify() {
    let mut rng = rand::thread_rng();
    let identity = Identity::generate(&mut rng).unwrap();
    let message = b"Hello, identity!";

    let signature = identity.sign(message);
    verify_signature(&identity.verifying_key(), message, &signature).unwrap();
}

#[test]
fn test_invalid_signature() {
    let mut rng = rand::thread_rng();
    let identity1 = Identity::generate(&mut rng).unwrap();
    let identity2 = Identity::generate(&mut rng).unwrap();
    let message = b"Test message";

    let signature = identity1.sign(message);
    let result = verify_signature(&identity2.verifying_key(), message, &signature);

    assert!(result.is_err());
}

#[test]
fn test_no_collisions() {
    use std::collections::HashSet;

    let mut public_keys = HashSet::new();
    for _ in 0..1000 {
        let mut rng = rand::thread_rng();
        let identity = Identity::generate(&mut rng).unwrap();
        assert!(public_keys.insert(identity.verifying_key().to_bytes()));
    }
    assert_eq!(public_keys.len(), 1000);
}

#[test]
fn test_public_key_hash() {
    let mut rng = rand::thread_rng();
    let identity = Identity::generate(&mut rng).unwrap();
    let hash = identity.public_key_hash();

    // Hash should be Blake3 (32 bytes)
    assert_eq!(hash.len(), 32);

    // Same identity should produce same hash
    assert_eq!(identity.public_key_hash(), hash);
}

#[test]
fn test_signing_key_bytes() {
    use secrecy::ExposeSecret;

    let seed = [123u8; 32];
    let identity = Identity::from_seed(&seed).unwrap();

    let secret_bytes = identity.signing_key_bytes();
    let bytes = secret_bytes.expose_secret();
    assert_eq!(bytes.len(), 32);

    // Reconstructing from bytes should give same public key
    let bytes_array: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let reconstructed = Identity::from_bytes(&bytes_array).unwrap();
    assert_eq!(
        identity.verifying_key().as_bytes(),
        reconstructed.verifying_key().as_bytes()
    );
}

#[test]
fn test_serializable_verifying_key() {
    use core_identity::SerializableVerifyingKey;

    let mut rng = rand::thread_rng();
    let identity = Identity::generate(&mut rng).unwrap();
    let public_key = identity.verifying_key();

    // Convert to serializable
    let serializable = SerializableVerifyingKey::from(&public_key);

    // Serialize to JSON
    let json = serde_json::to_string(&serializable).unwrap();
    assert!(!json.is_empty());

    // Deserialize back
    let deserialized: SerializableVerifyingKey = serde_json::from_str(&json).unwrap();
    assert_eq!(serializable, deserialized);

    // Convert back to VerifyingKey
    use std::convert::TryFrom;
    let reconstructed = ed25519_dalek::VerifyingKey::try_from(deserialized).unwrap();
    assert_eq!(public_key.as_bytes(), reconstructed.as_bytes());
}
