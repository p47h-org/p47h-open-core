//! Integration tests for ABAC Context Expression Parser
//!
//! These tests demonstrate the integration of ContextExpr with PolicyRule
//! and verify that the ABAC boolean expression parser works end-to-end.

use core_policy::builder::PolicyRuleBuilder;
use core_policy::context_expr::{CompareOp, ContextExpr};
use core_policy::{Action, PolicyRule, Resource};
use std::collections::BTreeMap;

#[test]
fn test_context_expr_integration_simple() {
    // Create a rule with a simple context expression
    let rule = PolicyRuleBuilder::new()
        .for_peer("alice")
        .allow(Action::Read)
        .on(Resource::File("/secure/*".into()))
        .with_context_expr("role == \"admin\"")
        .unwrap()
        .build()
        .unwrap();

    // Context where rule should match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    assert!(rule.matches_context(&context));

    // Context where rule should NOT match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "user".to_string());
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_integration_and() {
    // Create a rule with AND expression
    let rule = PolicyRuleBuilder::new()
        .for_peer("alice")
        .allow(Action::Write)
        .on(Resource::File("/data/*".into()))
        .with_context_expr("role == \"admin\" AND department == \"IT\"")
        .unwrap()
        .build()
        .unwrap();

    // Both conditions match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("department".to_string(), "IT".to_string());
    assert!(rule.matches_context(&context));

    // Only first condition matches
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("department".to_string(), "HR".to_string());
    assert!(!rule.matches_context(&context));

    // Only second condition matches
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "user".to_string());
    context.insert("department".to_string(), "IT".to_string());
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_integration_or() {
    // Create a rule with OR expression
    let rule = PolicyRuleBuilder::new()
        .for_peer("bob")
        .allow(Action::Read)
        .on(Resource::All)
        .with_context_expr("role == \"admin\" OR role == \"moderator\"")
        .unwrap()
        .build()
        .unwrap();

    // First condition matches
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    assert!(rule.matches_context(&context));

    // Second condition matches
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "moderator".to_string());
    assert!(rule.matches_context(&context));

    // Neither condition matches
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "user".to_string());
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_integration_not() {
    // Create a rule with NOT expression
    let rule = PolicyRuleBuilder::new()
        .for_peer("eve")
        .allow(Action::Execute)
        .on(Resource::File("/scripts/*".into()))
        .with_context_expr("NOT (status == \"banned\")")
        .unwrap()
        .build()
        .unwrap();

    // Status is not banned - should match
    let mut context = BTreeMap::new();
    context.insert("status".to_string(), "active".to_string());
    assert!(rule.matches_context(&context));

    // Status is banned - should NOT match
    let mut context = BTreeMap::new();
    context.insert("status".to_string(), "banned".to_string());
    assert!(!rule.matches_context(&context));

    // Status attribute missing - should match (NOT banned)
    let context = BTreeMap::new();
    assert!(rule.matches_context(&context));
}

#[test]
fn test_context_expr_integration_complex() {
    // Create a rule with complex nested expression
    let rule = PolicyRuleBuilder::new()
        .for_peer("charlie")
        .allow(Action::Write)
        .on(Resource::File("/sensitive/*".into()))
        .with_context_expr("(role == \"admin\" OR role == \"moderator\") AND active == \"true\"")
        .unwrap()
        .build()
        .unwrap();

    // Admin and active - should match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("active".to_string(), "true".to_string());
    assert!(rule.matches_context(&context));

    // Moderator and active - should match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "moderator".to_string());
    context.insert("active".to_string(), "true".to_string());
    assert!(rule.matches_context(&context));

    // Admin but not active - should NOT match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("active".to_string(), "false".to_string());
    assert!(!rule.matches_context(&context));

    // User and active - should NOT match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "user".to_string());
    context.insert("active".to_string(), "true".to_string());
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_integration_has_attribute() {
    // Create a rule that checks for attribute existence
    let rule = PolicyRuleBuilder::new()
        .for_peer("dave")
        .allow(Action::Read)
        .on(Resource::File("/logs/*".into()))
        .with_context_expr("HAS security_clearance")
        .unwrap()
        .build()
        .unwrap();

    // Has security_clearance - should match
    let mut context = BTreeMap::new();
    context.insert("security_clearance".to_string(), "top_secret".to_string());
    assert!(rule.matches_context(&context));

    // Missing security_clearance - should NOT match
    let context = BTreeMap::new();
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_integration_comparison_operators() {
    // Create a rule with comparison operators
    let rule = PolicyRuleBuilder::new()
        .for_peer("frank")
        .allow(Action::Read)
        .on(Resource::File("/age-restricted/*".into()))
        .with_context_expr("age >= \"18\"")
        .unwrap()
        .build()
        .unwrap();

    // Age 20 - should match (lexicographic comparison)
    let mut context = BTreeMap::new();
    context.insert("age".to_string(), "20".to_string());
    assert!(rule.matches_context(&context));

    // Age 18 - should match
    let mut context = BTreeMap::new();
    context.insert("age".to_string(), "18".to_string());
    assert!(rule.matches_context(&context));

    // Age 15 - should NOT match
    let mut context = BTreeMap::new();
    context.insert("age".to_string(), "15".to_string());
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_integration_combined_with_legacy_attributes() {
    // Create a rule with both legacy attributes AND context expression
    let rule = PolicyRuleBuilder::new()
        .for_peer("grace")
        .allow(Action::Write)
        .on(Resource::File("/shared/*".into()))
        .with_attribute("location", "office")
        .with_context_expr("role == \"admin\"")
        .unwrap()
        .build()
        .unwrap();

    // Both legacy attribute and expression match
    let mut context = BTreeMap::new();
    context.insert("location".to_string(), "office".to_string());
    context.insert("role".to_string(), "admin".to_string());
    assert!(rule.matches_context(&context));

    // Only expression matches - should NOT match (both must match)
    let mut context = BTreeMap::new();
    context.insert("location".to_string(), "remote".to_string());
    context.insert("role".to_string(), "admin".to_string());
    assert!(!rule.matches_context(&context));

    // Only legacy attribute matches - should NOT match
    let mut context = BTreeMap::new();
    context.insert("location".to_string(), "office".to_string());
    context.insert("role".to_string(), "user".to_string());
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_programmatic_construction() {
    // Create a rule with programmatically constructed expression
    let expr = ContextExpr::And(
        Box::new(ContextExpr::Compare {
            key: "role".into(),
            op: CompareOp::Equal,
            value: "admin".into(),
        }),
        Box::new(ContextExpr::Not(Box::new(ContextExpr::Compare {
            key: "status".into(),
            op: CompareOp::Equal,
            value: "suspended".into(),
        }))),
    );

    let rule =
        PolicyRule::new("heidi".into(), Action::Delete, Resource::All).with_context_expr(expr);

    // Admin and not suspended - should match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("status".to_string(), "active".to_string());
    assert!(rule.matches_context(&context));

    // Admin but suspended - should NOT match
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("status".to_string(), "suspended".to_string());
    assert!(!rule.matches_context(&context));
}

#[test]
fn test_context_expr_invalid_expression() {
    // Test that invalid expressions are properly rejected
    let result = PolicyRuleBuilder::new()
        .for_peer("mallory")
        .allow(Action::Read)
        .on(Resource::All)
        .with_context_expr("role = \"admin\""); // Single = is invalid

    assert!(result.is_err());
}

#[test]
fn test_context_expr_expression_too_long() {
    // Test that expressions exceeding MAX_EXPR_LENGTH are rejected
    let long_expr = "role == \"admin\"".repeat(100); // Creates very long expression

    let result = PolicyRuleBuilder::new()
        .for_peer("nancy")
        .allow(Action::Read)
        .on(Resource::All)
        .with_context_expr(&long_expr);

    assert!(result.is_err());
}
