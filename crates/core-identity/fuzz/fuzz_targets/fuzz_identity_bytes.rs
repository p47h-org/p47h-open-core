//! Fuzz target for Identity::from_bytes
//!
//! This target tests that Identity::from_bytes handles any 32-byte input
//! without panicking. Ed25519 signing keys can be created from any 32 bytes,
//! but we verify the entire flow is safe.

#![no_main]

use libfuzzer_sys::fuzz_target;
use core_identity::Identity;

fuzz_target!(|data: &[u8]| {
    // Test with arbitrary length data (most will fail, but shouldn't panic)
    if data.len() == 32 {
        // Exactly 32 bytes - valid input for from_bytes
        let bytes: [u8; 32] = data.try_into().unwrap();
        
        // This should NEVER panic - Ed25519 accepts any 32 bytes as seed
        let result = Identity::from_bytes(&bytes);
        
        if let Ok(identity) = result {
            // If we got an identity, verify we can use it safely
            let _public_key = identity.verifying_key();
            let _hash = identity.public_key_hash();
            
            // Sign something to verify the identity is usable
            let message = b"test message";
            let signature = identity.sign(message);
            
            // Verify the signature works
            let verifying_key = identity.verifying_key();
            let verify_result = core_identity::verify_signature(
                &verifying_key,
                message,
                &signature
            );
            
            // Signature should always be valid for a message we just signed
            assert!(verify_result.is_ok(), "Self-signed message must verify");
        }
    }
    
    // Also test from_seed with 32 bytes
    if data.len() >= 32 {
        let seed: [u8; 32] = data[..32].try_into().unwrap();
        let result = Identity::from_seed(&seed);
        
        if let Ok(identity) = result {
            // Determinism check: same seed should produce same identity
            let result2 = Identity::from_seed(&seed);
            if let Ok(identity2) = result2 {
                assert_eq!(
                    identity.verifying_key().as_bytes(),
                    identity2.verifying_key().as_bytes(),
                    "Same seed must produce same identity"
                );
            }
        }
    }
});
