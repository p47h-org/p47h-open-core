//! Tests for forced validation during Policy deserialization

use core_policy::{Policy, PolicyError, MAX_POLICY_NAME_LENGTH, MAX_RULES_PER_POLICY};

#[test]
fn test_deserialize_policy_with_too_many_rules() {
    // Create a TOML with more than MAX_RULES_PER_POLICY rules
    let mut toml = String::from(
        r#"
name = "test-policy"
version = 1
issued_at = 0
valid_until = 2000000000
"#,
    );

    // Add MAX_RULES_PER_POLICY + 1 rules
    for i in 0..=MAX_RULES_PER_POLICY {
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

    // Attempt to deserialize - should fail with TomlError containing TooManyRules message
    let result = Policy::from_toml(&toml);

    assert!(result.is_err(), "Expected error but got Ok");
    let err = result.unwrap_err();

    // The error is wrapped in TomlError by serde, but contains our PolicyError message
    match err {
        PolicyError::TomlError(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("1024"),
                "Error should mention max of 1024: {}",
                msg
            );
            assert!(
                msg.contains("1025"),
                "Error should mention attempted 1025: {}",
                msg
            );
        }
        other => panic!("Expected TomlError wrapping TooManyRules, got: {:?}", other),
    }
}

#[test]
fn test_deserialize_policy_with_too_long_name() {
    // Create a TOML with a name longer than MAX_POLICY_NAME_LENGTH
    let long_name = "a".repeat(MAX_POLICY_NAME_LENGTH + 1);
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
        long_name
    );

    // Attempt to deserialize - should fail with TomlError containing NameTooLong message
    let result = Policy::from_toml(&toml);

    assert!(result.is_err(), "Expected error but got Ok");
    let err = result.unwrap_err();

    match err {
        PolicyError::TomlError(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("128") || msg.contains("name"),
                "Error should mention name length limit: {}",
                msg
            );
        }
        other => panic!("Expected TomlError wrapping NameTooLong, got: {:?}", other),
    }
}

#[test]
fn test_deserialize_valid_policy() {
    let toml = r#"
name = "valid-policy"
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = { File = "/docs/*" }

[[rules]]
peer_id = "bob"
action = "Write"
resource = { File = "/logs/*" }
"#;

    let policy = Policy::from_toml(toml).unwrap();
    assert_eq!(policy.name(), "valid-policy");
    assert_eq!(policy.rules().len(), 2);
    assert_eq!(policy.version(), 1);
}

#[test]
fn test_deserialize_policy_with_empty_name() {
    let toml = r#"
name = ""
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = { File = "/test" }
"#;

    // Should fail validation due to empty name
    let result = Policy::from_toml(toml);
    assert!(result.is_err(), "Expected error but got Ok");

    let err = result.unwrap_err();
    match err {
        PolicyError::TomlError(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("empty") || msg.contains("name"),
                "Error should mention empty name: {}",
                msg
            );
        }
        other => panic!("Expected TomlError wrapping InvalidRule, got: {:?}", other),
    }
}

#[test]
fn test_deserialize_policy_with_no_rules() {
    let toml = r#"
name = "no-rules-policy"
version = 1
issued_at = 0
valid_until = 2000000000
"#;

    // Should fail validation due to no rules
    let result = Policy::from_toml(toml);
    assert!(result.is_err(), "Expected error but got Ok");

    let err = result.unwrap_err();
    match err {
        PolicyError::TomlError(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("rule") || msg.contains("at least one"),
                "Error should mention missing rules: {}",
                msg
            );
        }
        other => panic!("Expected TomlError wrapping InvalidRule, got: {:?}", other),
    }
}

#[test]
fn test_serialize_then_deserialize_roundtrip() {
    use core_policy::{Action, PolicyRule, Resource};

    // Create a policy programmatically
    let policy = Policy::new("roundtrip-test", 3600, 1000)
        .unwrap()
        .add_rule(PolicyRule::new(
            "alice".to_string(),
            Action::Read,
            Resource::File("/docs/*".to_string()),
        ))
        .unwrap()
        .with_metadata("owner", "admin");

    // Serialize to TOML
    let toml = policy.to_toml().unwrap();

    // Deserialize back
    let deserialized = Policy::from_toml(&toml).unwrap();

    // Verify all fields match
    assert_eq!(deserialized.name(), policy.name());
    assert_eq!(deserialized.version(), policy.version());
    assert_eq!(deserialized.issued_at(), policy.issued_at());
    assert_eq!(deserialized.valid_until(), policy.valid_until());
    assert_eq!(deserialized.rules().len(), policy.rules().len());
    assert_eq!(
        deserialized.metadata().get("owner"),
        policy.metadata().get("owner")
    );
}
