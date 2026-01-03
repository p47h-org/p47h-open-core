//! Unit tests for ABAC Context Expression Parser & Evaluator

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;
use core_policy::context_expr::{ContextExpr, MAX_EXPR_DEPTH};
use core_policy::error::PolicyError;

#[test]
fn test_tokenize_simple() {
    let expr = ContextExpr::parse("role == \"admin\"").unwrap();
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_tokenize_and() {
    let expr = ContextExpr::parse("role == \"admin\" AND dept == \"IT\"").unwrap();
    // Verify it parses without error - structure is tested in parse_and
    assert!(matches!(expr, ContextExpr::And(_, _)));
}

#[test]
fn test_parse_simple_comparison() {
    let expr = ContextExpr::parse("role == \"admin\"").unwrap();
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_parse_and() {
    let expr = ContextExpr::parse("role == \"admin\" AND dept == \"IT\"").unwrap();
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("dept".to_string(), "IT".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());

    context.insert("dept".to_string(), "HR".to_string());
    assert!(!expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_parse_or() {
    let expr = ContextExpr::parse("role == \"admin\" OR role == \"moderator\"").unwrap();
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());

    context.insert("role".to_string(), "moderator".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());

    context.insert("role".to_string(), "user".to_string());
    assert!(!expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_parse_not() {
    let expr = ContextExpr::parse("NOT (status == \"banned\")").unwrap();
    let mut context = BTreeMap::new();
    context.insert("status".to_string(), "active".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());

    context.insert("status".to_string(), "banned".to_string());
    assert!(!expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_parse_has_attribute() {
    let expr = ContextExpr::parse("HAS role").unwrap();
    let mut context = BTreeMap::new();
    assert!(!expr.evaluate(&context, 0).unwrap());

    context.insert("role".to_string(), "admin".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_parse_complex() {
    let expr =
        ContextExpr::parse("(role == \"admin\" OR role == \"moderator\") AND active == \"true\"")
            .unwrap();
    let mut context = BTreeMap::new();
    context.insert("role".to_string(), "admin".to_string());
    context.insert("active".to_string(), "true".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());

    context.insert("active".to_string(), "false".to_string());
    assert!(!expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_parse_comparison_operators() {
    let expr = ContextExpr::parse("age >= \"18\"").unwrap();
    let mut context = BTreeMap::new();
    context.insert("age".to_string(), "20".to_string());
    assert!(expr.evaluate(&context, 0).unwrap());

    context.insert("age".to_string(), "15".to_string());
    assert!(!expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_short_circuit_and() {
    let expr = ContextExpr::parse("FALSE AND (undefined_key == \"value\")").unwrap();
    let context = BTreeMap::new();
    // Should not fail even though undefined_key doesn't exist
    // because FALSE short-circuits the AND
    assert!(!expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_short_circuit_or() {
    let expr = ContextExpr::parse("TRUE OR (undefined_key == \"value\")").unwrap();
    let context = BTreeMap::new();
    // Should not fail even though undefined_key doesn't exist
    // because TRUE short-circuits the OR
    assert!(expr.evaluate(&context, 0).unwrap());
}

#[test]
fn test_max_depth() {
    // Create a deeply nested expression
    let mut expr_str = "TRUE".to_string();
    for _ in 0..MAX_EXPR_DEPTH + 1 {
        expr_str = format!("NOT ({})", expr_str);
    }

    let expr = ContextExpr::parse(&expr_str).unwrap();
    let context = BTreeMap::new();
    let result = expr.evaluate(&context, 0);
    assert!(matches!(result, Err(PolicyError::ExpressionTooDeep { .. })));
}

#[test]
fn test_max_length() {
    let long_expr = "role == \"admin\"".repeat(100);
    let result = ContextExpr::parse(&long_expr);
    assert!(matches!(result, Err(PolicyError::ExpressionTooLong { .. })));
}

#[test]
fn test_invalid_syntax() {
    assert!(ContextExpr::parse("role = \"admin\"").is_err()); // Single =
    assert!(ContextExpr::parse("role == ").is_err()); // Missing value
    assert!(ContextExpr::parse("== \"admin\"").is_err()); // Missing key
    assert!(ContextExpr::parse("(role == \"admin\"").is_err()); // Unmatched paren
}
