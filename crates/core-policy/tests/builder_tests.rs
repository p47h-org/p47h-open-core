//! Integration tests for PolicyBuilder and PolicyRuleBuilder

use core_policy::{Action, PolicyBuilder, PolicyRuleBuilder, Resource};

#[test]
fn test_policy_rule_builder() {
    let rule = PolicyRuleBuilder::new()
        .for_peer("12D3KooWTest")
        .allow(Action::read())
        .on(Resource::file("/docs/*"))
        .build()
        .unwrap();

    assert_eq!(rule.peer_id, "12D3KooWTest");
    assert_eq!(rule.action, Action::Read);
    assert!(matches!(rule.resource, Resource::File(_)));
}

#[test]
fn test_policy_rule_builder_missing_fields() {
    let result = PolicyRuleBuilder::new().for_peer("12D3KooWTest").build();

    assert!(result.is_err());
}

#[test]
fn test_policy_builder() {
    let policy = PolicyBuilder::new("test-policy")
        .add_rule_with(|rule| {
            rule.for_peer("12D3KooWAlice")
                .allow(Action::all())
                .on(Resource::all())
        })
        .add_rule_with(|rule| {
            rule.for_peer("12D3KooWBob")
                .allow(Action::read())
                .on(Resource::file("/docs/*"))
        })
        .with_metadata("owner", "alice")
        .build()
        .unwrap();

    assert_eq!(policy.name(), "test-policy");
    assert_eq!(policy.rules().len(), 2);
    assert_eq!(policy.metadata().get("owner"), Some(&"alice".to_string()));
}

/// Example usage of PolicyRuleBuilder
///
/// ```
/// use core_policy::{PolicyRuleBuilder, Action, Resource};
///
/// let rule = PolicyRuleBuilder::new()
///     .for_peer("12D3KooWTest")
///     .allow(Action::read())
///     .on(Resource::file("/docs/*"))
///     .build()
///     .unwrap();
/// ```
#[test]
fn test_policy_rule_builder_doctest() {
    let rule = PolicyRuleBuilder::new()
        .for_peer("12D3KooWTest")
        .allow(Action::read())
        .on(Resource::file("/docs/*"))
        .build()
        .unwrap();

    assert_eq!(rule.peer_id, "12D3KooWTest");
}

/// Example usage of PolicyBuilder
///
/// ```
/// use core_policy::{PolicyBuilder, Action, Resource};
///
/// let policy = PolicyBuilder::new("my-policy")
///     .add_rule_with(|rule| {
///         rule.for_peer("12D3KooWTest")
///             .allow(Action::read())
///             .on(Resource::file("/docs/*"))
///     })
///     .build()
///     .unwrap();
/// ```
#[test]
fn test_policy_builder_doctest() {
    let policy = PolicyBuilder::new("my-policy")
        .add_rule_with(|rule| {
            rule.for_peer("12D3KooWTest")
                .allow(Action::read())
                .on(Resource::file("/docs/*"))
        })
        .build()
        .unwrap();

    assert_eq!(policy.name(), "my-policy");
    assert_eq!(policy.rules().len(), 1);
}
