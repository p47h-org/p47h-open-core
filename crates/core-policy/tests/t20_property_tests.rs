//! Property-based tests for T20 validation limits
//!
//! These tests ensure that Policy deserialization enforces:
//! - MAX_POLICY_NAME_LENGTH (128)
//! - MAX_RULES_PER_POLICY (1024)
//! - At least one rule required

use core_policy::{
    Action, Policy, PolicyRule, Resource, MAX_POLICY_NAME_LENGTH, MAX_RULES_PER_POLICY,
};
use proptest::prelude::*;

/// Generate arbitrary valid policy names (within limits)
fn arb_valid_policy_name() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z][a-zA-Z0-9_-]{0,126}")
        .unwrap()
        .prop_filter("non-empty", |s| !s.is_empty())
}

// =============================================================================
// T20 PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Any policy with a valid name should be deserializable
    #[test]
    fn prop_valid_name_deserializes(name in arb_valid_policy_name()) {
        let toml = format!(
            r#"
name = "{}"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = {{ File = "/test" }}
"#,
            name
        );

        let result = Policy::from_toml(&toml);
        prop_assert!(result.is_ok(), "Valid policy name '{}' should deserialize: {:?}", name, result);
        let policy = result.unwrap();
        prop_assert_eq!(policy.name(), &name);
    }

    /// Property: Names exactly at MAX_POLICY_NAME_LENGTH should be valid
    #[test]
    fn prop_max_length_name_valid(char_choice in proptest::collection::vec(prop_oneof![Just('a'), Just('b'), Just('_'), Just('-')], MAX_POLICY_NAME_LENGTH..=MAX_POLICY_NAME_LENGTH)) {
        // Generate name that's exactly MAX_POLICY_NAME_LENGTH using valid chars
        let name: String = char_choice.into_iter().collect();
        prop_assert_eq!(name.len(), MAX_POLICY_NAME_LENGTH);

        let toml = format!(
            r#"
name = "{}"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = {{ File = "/test" }}
"#,
            name
        );

        let result = Policy::from_toml(&toml);
        prop_assert!(result.is_ok(), "Max-length name ({} chars) should be valid: {:?}", name.len(), result);
    }

    /// Property: Names longer than MAX_POLICY_NAME_LENGTH must be rejected
    #[test]
    fn prop_too_long_name_rejected(extra_len in 1usize..100) {
        let name = "a".repeat(MAX_POLICY_NAME_LENGTH + extra_len);

        let toml = format!(
            r#"
name = "{}"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = {{ File = "/test" }}
"#,
            name
        );

        let result = Policy::from_toml(&toml);
        prop_assert!(result.is_err(), "Name with {} chars (>{}) must be rejected", name.len(), MAX_POLICY_NAME_LENGTH);
    }

    /// Property: Policies with rule count in valid range should deserialize
    #[test]
    fn prop_valid_rule_count_deserializes(rule_count in 1usize..=20) {
        let mut toml = String::from(
            r#"
name = "test-policy"
version = 1
issued_at = 0
valid_until = 2000000000
"#,
        );

        for i in 0..rule_count {
            toml.push_str(&format!(
                r#"
[[rules]]
peer_id = "peer{}"
action = "Read"
resource = {{ File = "/test/{}" }}
"#,
                i, i
            ));
        }

        let result = Policy::from_toml(&toml);
        prop_assert!(result.is_ok(), "Policy with {} rules should deserialize: {:?}", rule_count, result);
        prop_assert_eq!(result.unwrap().rules().len(), rule_count);
    }

    /// Property: Policy with >MAX_RULES_PER_POLICY rules must be rejected
    /// Note: This test uses a smaller sample to avoid extremely slow test execution
    #[test]
    fn prop_too_many_rules_rejected(extra in 1usize..5) {
        let rule_count = MAX_RULES_PER_POLICY + extra;
        let mut toml = String::from(
            r#"
name = "test-policy"
version = 1
issued_at = 0
valid_until = 2000000000
"#,
        );

        for i in 0..rule_count {
            toml.push_str(&format!(
                r#"
[[rules]]
peer_id = "peer{}"
action = "Read"
resource = {{ File = "/test" }}
"#,
                i
            ));
        }

        let result = Policy::from_toml(&toml);
        prop_assert!(result.is_err(), "Policy with {} rules (>{}) must be rejected", rule_count, MAX_RULES_PER_POLICY);
    }

    /// Property: Any deserialized policy must pass validate()
    #[test]
    fn prop_deserialized_policy_is_valid(
        name in arb_valid_policy_name(),
        rule_count in 1usize..=10
    ) {
        let mut toml = format!(
            r#"
name = "{}"
version = 1
issued_at = 0
valid_until = 2000000000
"#,
            name
        );

        for i in 0..rule_count {
            toml.push_str(&format!(
                r#"
[[rules]]
peer_id = "peer{}"
action = "Read"
resource = {{ File = "/path/{}" }}
"#,
                i, i
            ));
        }

        let result = Policy::from_toml(&toml);
        if let Ok(policy) = result {
            prop_assert!(policy.validate().is_ok(), "Deserialized policy must pass validate()");
        }
        // If deserialization fails, that's fine - we're testing that valid TOMLs produce valid policies
    }

    /// Property: Serialized then deserialized policy should be equivalent
    #[test]
    fn prop_roundtrip_preserves_validity(
        name in arb_valid_policy_name(),
        rule_count in 1usize..=5
    ) {
        // Build policy programmatically
        let mut policy = match Policy::new(&name, 3600, 1000) {
            Ok(p) => p,
            Err(_) => return Ok(()), // Invalid name, skip
        };

        for i in 0..rule_count {
            policy = policy.add_rule(PolicyRule::new(
                format!("peer{}", i),
                Action::Read,
                Resource::File(format!("/path/{}", i)),
            )).unwrap();
        }

        // Roundtrip
        let toml = policy.to_toml().unwrap();
        let deserialized = Policy::from_toml(&toml);

        prop_assert!(deserialized.is_ok(), "Roundtrip should preserve validity: {:?}", deserialized);
        let p2 = deserialized.unwrap();
        prop_assert_eq!(p2.name(), policy.name());
        prop_assert_eq!(p2.rules().len(), policy.rules().len());
    }
}

// =============================================================================
// DETERMINISTIC T20 BOUNDARY TESTS
// =============================================================================

#[test]
fn test_t20_boundary_name_127() {
    // One less than max - should work
    let name = "a".repeat(MAX_POLICY_NAME_LENGTH - 1);
    let toml = format!(
        r#"
name = "{}"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = {{ File = "/test" }}
"#,
        name
    );
    assert!(Policy::from_toml(&toml).is_ok());
}

#[test]
fn test_t20_boundary_name_128() {
    // Exactly max - should work
    let name = "a".repeat(MAX_POLICY_NAME_LENGTH);
    let toml = format!(
        r#"
name = "{}"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = {{ File = "/test" }}
"#,
        name
    );
    assert!(Policy::from_toml(&toml).is_ok());
}

#[test]
fn test_t20_boundary_name_129() {
    // One more than max - must fail
    let name = "a".repeat(MAX_POLICY_NAME_LENGTH + 1);
    let toml = format!(
        r#"
name = "{}"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = {{ File = "/test" }}
"#,
        name
    );
    assert!(Policy::from_toml(&toml).is_err());
}

#[test]
fn test_t20_boundary_rules_0() {
    // Zero rules - must fail
    let toml = r#"
name = "test"
version = 1
issued_at = 0
valid_until = 2000000000
"#;
    assert!(Policy::from_toml(toml).is_err());
}

#[test]
fn test_t20_boundary_rules_1() {
    // One rule - should work
    let toml = r#"
name = "test"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = { File = "/test" }
"#;
    assert!(Policy::from_toml(toml).is_ok());
}
