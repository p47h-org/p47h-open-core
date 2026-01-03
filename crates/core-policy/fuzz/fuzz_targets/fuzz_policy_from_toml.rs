//! Fuzz target for Policy::from_toml
//!
//! This target tests that Policy deserialization handles arbitrary TOML
//! input without panicking, and validates T20 limits are enforced.

#![no_main]

use libfuzzer_sys::fuzz_target;
use core_policy::Policy;

fuzz_target!(|data: &str| {
    // Test: Policy::from_toml should never panic on any input
    // It may return Ok or Err, but should never crash
    let result = Policy::from_toml(data);
    
    // If parsing succeeds, verify the policy is valid
    if let Ok(policy) = result {
        // T20 invariants should hold:
        // 1. Name length <= MAX_POLICY_NAME_LENGTH (128)
        assert!(policy.name().len() <= 128, "Policy name exceeds limit");
        
        // 2. Rules count <= MAX_RULES_PER_POLICY (1024)
        assert!(policy.rules().len() <= 1024, "Rules count exceeds limit");
        
        // 3. Policy should be valid
        assert!(policy.validate().is_ok(), "Parsed policy failed validation");
        
        // Test that we can access all fields without panic
        let _ = policy.version();
        let _ = policy.issued_at();
        let _ = policy.valid_until();
        let _ = policy.metadata();
    }
});
