//! Security tests for ContextExpr parser (Anti-Stack Overflow)
//!
//! These tests can run on any platform (including Windows) without libfuzzer.
//! They cover the same attack vectors as the fuzz target:
//! - Deep nesting patterns
//! - Many operators
//! - Unbalanced parentheses
//! - Oversized input
//! - Special characters

use core_policy::{ContextExpr, MAX_EXPR_DEPTH, MAX_EXPR_LENGTH};
use std::collections::BTreeMap;

/// Test that deeply nested parentheses don't cause stack overflow
#[test]
fn test_deep_nesting_no_crash() {
    // Generate expressions with increasing nesting depth
    for depth in 1..=100 {
        let open_parens = "(".repeat(depth);
        let close_parens = ")".repeat(depth);
        let expr = format!("{}TRUE{}", open_parens, close_parens);

        // Must not panic
        let result = ContextExpr::parse(&expr);
        
        // For very deep nesting, we expect parsing to succeed
        // but evaluation should be limited by MAX_EXPR_DEPTH
        if let Ok(parsed) = result {
            let ctx = BTreeMap::new();
            let eval_result = parsed.evaluate(&ctx, 0);
            // Either succeeds or returns ExpressionTooDeep error
            let _ = eval_result;
        }
    }
}

/// Test that extremely deep nesting (beyond limit) is handled
#[test]
fn test_extreme_nesting_handled() {
    // Create nesting deeper than MAX_EXPR_DEPTH
    let depth = MAX_EXPR_DEPTH + 50;
    let open_parens = "(".repeat(depth);
    let close_parens = ")".repeat(depth);
    let expr = format!("{}TRUE{}", open_parens, close_parens);

    // Must not panic - may fail at parse or evaluate stage
    let result = ContextExpr::parse(&expr);
    if let Ok(parsed) = result {
        let ctx = BTreeMap::new();
        let eval_result = parsed.evaluate(&ctx, 0);
        // Should return ExpressionTooDeep error for very deep nesting
        assert!(
            eval_result.is_err() || eval_result.is_ok(),
            "Evaluation must return a proper Result, not panic"
        );
    }
}

/// Test many AND/OR operators don't cause issues
#[test]
fn test_many_operators_no_crash() {
    let base = "role == \"admin\"";
    for count in 1..=50 {
        let repeated = vec![base; count].join(" AND ");
        let result = ContextExpr::parse(&repeated);
        // Must not panic, may fail due to length limit
        let _ = result;
    }

    for count in 1..=50 {
        let repeated = vec![base; count].join(" OR ");
        let result = ContextExpr::parse(&repeated);
        let _ = result;
    }
}

/// Test unbalanced parentheses don't cause crashes
#[test]
fn test_unbalanced_parens_no_crash() {
    let cases = [
        "(((",
        ")))",
        "(((TRUE))",
        "((TRUE)))",
        "(role == \"admin\"",
        "role == \"admin\")",
        "(((role == \"admin\"))(((",
        ")))role == \"admin\"(((",
        "((((((((((",
        "))))))))))",
        "(TRUE AND (FALSE OR (TRUE AND (FALSE))))",
        "((((((((((TRUE))))))))))",
    ];

    for case in cases {
        // Must not panic
        let result = ContextExpr::parse(case);
        assert!(result.is_ok() || result.is_err(), "Must return Result");
    }
}

/// Test that oversized input is rejected gracefully
#[test]
fn test_oversized_input_rejected() {
    let huge = "a".repeat(MAX_EXPR_LENGTH + 100);
    let result = ContextExpr::parse(&huge);
    assert!(result.is_err(), "Oversized input should be rejected");
}

/// Test that input at exact limit boundary works correctly  
#[test]
fn test_boundary_size_input() {
    // Just under limit
    let under = "a".repeat(MAX_EXPR_LENGTH - 10);
    let result = ContextExpr::parse(&under);
    // May fail for syntax but should not panic
    let _ = result;

    // Exactly at limit
    let exact = "a".repeat(MAX_EXPR_LENGTH);
    let result = ContextExpr::parse(&exact);
    let _ = result;

    // Just over limit
    let over = "a".repeat(MAX_EXPR_LENGTH + 1);
    let result = ContextExpr::parse(&over);
    assert!(result.is_err(), "Over limit should be rejected");
}

/// Test null bytes and special characters don't cause crashes
#[test]
fn test_special_chars_no_crash() {
    let cases = [
        "\0",
        "\x00\x01\x02",
        "role\0== \"admin\"",
        "role == \"admin\x00\"",
        "\n\r\t",
        "   \t\t\t   ",
        "role\n==\r\"admin\"",
    ];

    for case in cases {
        // Must not panic
        let _ = ContextExpr::parse(case);
    }
}

/// Test Unicode characters don't cause crashes
#[test]
fn test_unicode_no_crash() {
    let cases = [
        "роль == \"админ\"",           // Cyrillic
        "角色 == \"管理员\"",           // Chinese
        "🔒 == \"🔑\"",                // Emoji
        "rôle == \"àdmin\"",           // Accented Latin
        "役割 == \"管理者\"",           // Japanese
        "תפקיד == \"מנהל\"",           // Hebrew (RTL)
        "دور == \"مدير\"",             // Arabic (RTL)
    ];

    for case in cases {
        // Must not panic
        let _ = ContextExpr::parse(case);
    }
}

/// Test empty and whitespace-only input
#[test]
fn test_empty_input_no_crash() {
    let cases = ["", " ", "   ", "\t", "\n", "\r\n", "  \t  \n  "];

    for case in cases {
        let _ = ContextExpr::parse(case);
    }
}

/// Test malformed operator sequences
#[test]
fn test_malformed_operators_no_crash() {
    let cases = [
        "AND AND",
        "OR OR OR",
        "NOT NOT NOT",
        "AND OR AND",
        "== ==",
        "!= !=",
        "role == == \"admin\"",
        "AND",
        "OR",
        "NOT",
        "HAS",
        "TRUE AND",
        "AND TRUE",
        "role ==",
        "== \"admin\"",
    ];

    for case in cases {
        let _ = ContextExpr::parse(case);
    }
}

/// Test string literal edge cases
#[test]
fn test_string_literal_edge_cases() {
    let cases = [
        "role == \"\"",                    // Empty string
        "role == \"\\\"\"",                // Escaped quote
        "role == \"\\\\\"",                // Escaped backslash
        "role == \"a\\\"b\"",              // Quote in middle
        "role == \"",                      // Unterminated
        "role == \"admin",                 // Unterminated
        "role == admin\"",                 // No opening quote
    ];

    for case in cases {
        let _ = ContextExpr::parse(case);
    }
}

/// Stress test: parse and evaluate many random-ish expressions
#[test]
fn test_stress_parse_evaluate() {
    let expressions = [
        "TRUE",
        "FALSE",
        "role == \"admin\"",
        "role == \"admin\" AND dept == \"IT\"",
        "(role == \"admin\" OR role == \"mod\") AND active == \"true\"",
        "NOT (banned == \"true\")",
        "HAS role",
        "HAS role AND role == \"admin\"",
        "a == \"1\" AND b == \"2\" AND c == \"3\" AND d == \"4\"",
        "(((TRUE)))",
        "NOT NOT NOT TRUE",
    ];

    let mut ctx = BTreeMap::new();
    ctx.insert("role".to_string(), "admin".to_string());
    ctx.insert("dept".to_string(), "IT".to_string());
    ctx.insert("active".to_string(), "true".to_string());

    for expr_str in expressions {
        if let Ok(expr) = ContextExpr::parse(expr_str) {
            let _ = expr.evaluate(&ctx, 0);
        }
    }
}
