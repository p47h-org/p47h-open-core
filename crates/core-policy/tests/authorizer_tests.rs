//! Integration tests for PolicyAuthorizer

use core_policy::{Action, Authorizer, PolicyAuthorizer, PolicyRule, Resource};
use std::collections::BTreeMap;

#[test]
fn test_authorizer_is_allowed() {
    let rules = vec![
        PolicyRule::new("alice".into(), Action::Read, Resource::All),
        PolicyRule::new("bob".into(), Action::Write, Resource::File("/tmp/*".into())),
    ];
    let auth = PolicyAuthorizer::new(&rules);

    // Alice can read anything
    assert!(auth.is_allowed("alice", &Action::Read, &Resource::File("/test".into())));
    assert!(auth.is_allowed("alice", &Action::Read, &Resource::Usb("device1".into())));

    // Bob can only write to /tmp/*
    assert!(auth.is_allowed("bob", &Action::Write, &Resource::File("/tmp/file".into())));
    assert!(!auth.is_allowed("bob", &Action::Write, &Resource::File("/home/file".into())));
    assert!(!auth.is_allowed("bob", &Action::Read, &Resource::File("/tmp/file".into())));

    // Charlie has no permissions
    assert!(!auth.is_allowed("charlie", &Action::Read, &Resource::All));
}

#[test]
fn test_authorizer_matching_rules() {
    let rules = vec![
        PolicyRule::new("alice".into(), Action::Read, Resource::All),
        PolicyRule::new(
            "alice".into(),
            Action::Read,
            Resource::File("/docs/*".into()),
        ),
        PolicyRule::new("bob".into(), Action::Read, Resource::All),
    ];
    let auth = PolicyAuthorizer::new(&rules);

    // Alice should have 2 matching rules for reading (one All, one specific pattern that matches)
    let resource = Resource::File("/docs/file".into());
    let matches: Vec<_> = auth
        .matching_rules("alice", &Action::Read, &resource)
        .collect();
    // Both Resource::All and Resource::File("/docs/*") should match
    assert_eq!(matches.len(), 2);

    // Bob should have 1 matching rule (only Resource::All)
    let resource = Resource::File("/docs/file".into());
    let matches: Vec<_> = auth
        .matching_rules("bob", &Action::Read, &resource)
        .collect();
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_authorizer_with_context() {
    let rule_with_expiration = PolicyRule::with_expiration(
        "alice".into(),
        Action::Read,
        Resource::All,
        1000, // expires at timestamp 1000
    );

    let rules = vec![rule_with_expiration];
    let auth = PolicyAuthorizer::new(&rules);

    let mut context = BTreeMap::new();
    context.insert("timestamp".to_string(), "999".to_string());

    // Before expiration - should be allowed
    assert!(auth.is_allowed_with_context(
        "alice",
        &Action::Read,
        &Resource::File("/test".into()),
        999, // current_time
        &context
    ));

    // After expiration - should be denied
    context.insert("timestamp".to_string(), "1001".to_string());
    assert!(!auth.is_allowed_with_context(
        "alice",
        &Action::Read,
        &Resource::File("/test".into()),
        1001, // current_time
        &context
    ));
}

#[test]
fn test_authorizer_with_attributes() {
    let mut rule = PolicyRule::new("alice".into(), Action::Read, Resource::All);
    rule.attributes
        .insert("role".to_string(), "admin".to_string());

    let rules = vec![rule];
    let auth = PolicyAuthorizer::new(&rules);

    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());

    // Matching attributes - allowed
    assert!(auth.is_allowed_with_context(
        "alice",
        &Action::Read,
        &Resource::File("/test".into()),
        0, // current_time (no expiration)
        &context
    ));

    // Non-matching attributes - denied
    context.insert("role".to_string(), "user".to_string());
    assert!(!auth.is_allowed_with_context(
        "alice",
        &Action::Read,
        &Resource::File("/test".into()),
        0, // current_time
        &context
    ));
}

#[test]
fn test_authorizer_rule_count() {
    let rules = vec![
        PolicyRule::new("alice".into(), Action::Read, Resource::All),
        PolicyRule::new("bob".into(), Action::Write, Resource::All),
    ];
    let auth = PolicyAuthorizer::new(&rules);

    assert_eq!(auth.rule_count(), 2);
}

#[test]
fn test_authorizer_trait_implementation() {
    let rules = vec![PolicyRule::new("alice".into(), Action::Read, Resource::All)];
    let auth = PolicyAuthorizer::new(&rules);

    // Test that PolicyAuthorizer implements Authorizer trait
    fn check_authorization<A: Authorizer>(authorizer: &A, peer: &str) -> bool {
        authorizer.is_allowed(peer, &Action::Read, &Resource::File("/test".into()))
    }

    assert!(check_authorization(&auth, "alice"));
    assert!(!check_authorization(&auth, "bob"));
}

#[test]
fn test_authorizer_empty_rules() {
    let rules: Vec<PolicyRule> = vec![];
    let auth = PolicyAuthorizer::new(&rules);

    // No rules - should deny everything
    assert!(!auth.is_allowed("alice", &Action::Read, &Resource::All));
    assert_eq!(auth.rule_count(), 0);
}
