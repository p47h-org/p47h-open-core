//! Integration tests for Policy domain types

use core_policy::{
    Action, Policy, PolicyError, PolicyRule, Resource, MAX_POLICY_NAME_LENGTH, MAX_RULES_PER_POLICY,
};

#[test]
fn test_action_matches() {
    assert!(Action::Read.matches(&Action::Read));
    assert!(!Action::Read.matches(&Action::Write));
    assert!(Action::All.matches(&Action::Read));
    assert!(Action::Read.matches(&Action::All));
}

#[test]
fn test_resource_file_pattern() {
    let pattern = Resource::File("/home/*/docs".to_string());
    let path = Resource::File("/home/alice/docs".to_string());
    assert!(pattern.matches(&path));
}

#[test]
fn test_policy_rule_allows() {
    let rule = PolicyRule::new(
        "alice".to_string(),
        Action::Read,
        Resource::File("/docs/*".to_string()),
    );

    assert!(rule.allows(
        "alice",
        &Action::Read,
        &Resource::File("/docs/file.txt".to_string())
    ));
    assert!(!rule.allows(
        "bob",
        &Action::Read,
        &Resource::File("/docs/file.txt".to_string())
    ));
}

#[test]
fn test_policy_rule_expiration() {
    let rule = PolicyRule::with_expiration("alice".to_string(), Action::Read, Resource::All, 1000);

    assert!(rule.is_expired(1001));
    assert!(!rule.is_expired(999));
}

#[test]
fn test_policy_add_rule() {
    let policy = Policy::new("test", 3600, 0).unwrap();
    let rule = PolicyRule::new("alice".to_string(), Action::Read, Resource::All);

    let policy = policy.add_rule(rule).unwrap();
    assert_eq!(policy.rules().len(), 1);
}

#[test]
fn test_policy_max_rules() {
    let mut policy = Policy::new("test", 3600, 0).unwrap();

    // Add maximum allowed rules
    for i in 0..MAX_RULES_PER_POLICY {
        let rule = PolicyRule::new(format!("peer{}", i), Action::Read, Resource::All);
        policy = policy.add_rule(rule).unwrap();
    }

    // Try to add one more
    let extra_rule = PolicyRule::new("extra".to_string(), Action::Read, Resource::All);
    let result = policy.add_rule(extra_rule);

    assert!(matches!(result, Err(PolicyError::TooManyRules { .. })));
}

#[test]
fn test_policy_name_length_limit() {
    let long_name = "a".repeat(MAX_POLICY_NAME_LENGTH + 1);
    let result = Policy::new(long_name, 3600, 0);
    assert!(matches!(result, Err(PolicyError::NameTooLong { .. })));
}
