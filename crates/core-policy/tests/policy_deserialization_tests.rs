//! Tests for forced validation during Policy deserialization

use core_policy::{Policy, MAX_POLICY_NAME_LENGTH, MAX_RULES_PER_POLICY};

#[test]
fn test_deserialize_policy_with_too_many_rules() {
    // Create a TOML with more than MAX_RULES_PER_POLICY rules
    let mut toml_str = String::from(
        r#"
name = "test-policy"
version = 1
issued_at = 0
valid_until = 2000000000
"#,
    );

    // Add MAX_RULES_PER_POLICY + 1 rules
    for i in 0..=MAX_RULES_PER_POLICY {
        toml_str.push_str(&format!(
            r#"
[[rules]]
peer_id = "peer{}"
action = "Read"
resource = {{ File = "/test" }}
"#,
            i
        ));
    }

    // Attempt to deserialize - should fail with TooManyRules wrapped in toml error
    let result = toml::from_str::<Policy>(&toml_str);

    assert!(result.is_err(), "Expected error but got Ok");
    let msg = result.unwrap_err().to_string();

    // The PolicyError message is embedded in the toml::de::Error string
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

#[test]
fn test_deserialize_policy_with_too_long_name() {
    // Create a TOML with a name longer than MAX_POLICY_NAME_LENGTH
    let long_name = "a".repeat(MAX_POLICY_NAME_LENGTH + 1);
    let toml_str = format!(
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

    let result = toml::from_str::<Policy>(&toml_str);

    assert!(result.is_err(), "Expected error but got Ok");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("128") || msg.contains("name"),
        "Error should mention name length limit: {}",
        msg
    );
}

#[test]
fn test_deserialize_valid_policy() {
    let toml_str = r#"
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

    let policy = toml::from_str::<Policy>(toml_str).unwrap();
    assert_eq!(policy.name(), "valid-policy");
    assert_eq!(policy.rules().len(), 2);
    assert_eq!(policy.version(), 1);
}

#[test]
fn test_deserialize_policy_with_empty_name() {
    let toml_str = r#"
name = ""
version = 1
issued_at = 0
valid_until = 2000000000

[[rules]]
peer_id = "alice"
action = "Read"
resource = { File = "/test" }
"#;

    let result = toml::from_str::<Policy>(toml_str);
    assert!(result.is_err(), "Expected error but got Ok");

    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("empty") || msg.contains("name"),
        "Error should mention empty name: {}",
        msg
    );
}

#[test]
fn test_deserialize_policy_with_no_rules() {
    let toml_str = r#"
name = "no-rules-policy"
version = 1
issued_at = 0
valid_until = 2000000000
"#;

    let result = toml::from_str::<Policy>(toml_str);
    assert!(result.is_err(), "Expected error but got Ok");

    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("rule") || msg.contains("at least one"),
        "Error should mention missing rules: {}",
        msg
    );
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
    let toml_str = toml::to_string(&policy).unwrap();

    // Deserialize back
    let deserialized = toml::from_str::<Policy>(&toml_str).unwrap();

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
