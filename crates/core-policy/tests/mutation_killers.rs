//! Mutation Testing Kill Tests
//!
//! These tests are specifically designed to kill mutants that survived
//! the initial mutation testing run. Each test targets a specific mutation.
//!
//! Run: cargo test --test mutation_killers

use core_policy::{ContextExpr, CompareOp, PolicyError, MAX_EXPR_DEPTH, MAX_EXPR_LENGTH};
use std::collections::BTreeMap;

// ============================================================================
// KILL: depth + 1 -> depth * 1 mutations (THE CRITICAL ONE)
//
// WHY THIS MATTERS: If depth + 1 becomes depth * 1 and we start with depth=0,
// then 0 * 1 = 0. The depth counter NEVER increments. This completely
// disables the stack overflow protection, allowing infinite recursion.
//
// This test MUST use matches! with the specific error type to guarantee
// the test fails when the mutant is applied.
// ============================================================================

/// This test KILLS the depth * 1 mutant by explicitly checking for ExpressionTooDeep.
/// 
/// The mutant changes `depth + 1` to `depth * 1`:
/// - Normal code: depth increments 0 → 1 → 2 → ... → 33 (fails at 33 > 32)  
/// - Mutant code: depth stays at 0 forever (0 * 1 = 0), never triggers the check
///
/// If the mutant is applied, this test returns Ok instead of Err, KILLING the mutant.
#[test]
fn kill_depth_mutation() {
    // Create expression with depth 33 (MAX is 32)
    // NOT(NOT(NOT(...NOT(TRUE)...))) with 33 levels
    let mut expr = ContextExpr::True;
    for _ in 0..=MAX_EXPR_DEPTH { // 0..=32 = 33 iterations
        expr = ContextExpr::Not(Box::new(expr));
    }
    
    let ctx = BTreeMap::new();
    
    // The original code returns Err(ExpressionTooDeep).
    // The mutant (depth * 1) returns Ok, because depth never goes above 1.
    // This assert MUST verify it's specifically ExpressionTooDeep error.
    let result = expr.evaluate(&ctx, 0);
    assert!(
        matches!(result, Err(PolicyError::ExpressionTooDeep { .. })),
        "Expected ExpressionTooDeep error for depth {}, got {:?}",
        MAX_EXPR_DEPTH + 1,
        result
    );
}

// ============================================================================
// KILL: depth + 1 -> depth * 1 mutations (lines 193, 197, 202, 206)
// 
// INSIGHT: If depth + 1 becomes depth * 1, and we start with depth=0,
// then 0 * 1 = 0, so depth NEVER increments. The check `depth > MAX_EXPR_DEPTH`
// would never trigger because depth stays at 0 forever.
//
// TO KILL THIS MUTANT: We need to verify that at exactly MAX_EXPR_DEPTH + 2 
// nesting levels, the evaluate() function returns ExpressionTooDeep error.
// With the mutant, it would succeed (depth stays 0), without it fails.
// ============================================================================

/// Test that nested AND correctly tracks depth and rejects too-deep expressions.
/// This test constructs expressions MANUALLY (not via parser) to bypass length limits.
/// 
/// The mutant changes `depth + 1` to `depth * 1`, so:
/// - Normal: depth goes 0 -> 1 -> 2 -> ... -> 33 (fails at 33 > 32)
/// - Mutant: depth goes 0 -> 0 -> 0 -> ... -> 0 (never fails)
#[test]
fn kill_depth_increment_and_surgical() {
    // Build expression manually: AND(AND(AND(...(TRUE)...))) 
    // Nesting depth = N means we need N+1 evaluate calls to reach the inner TRUE
    fn build_nested_and(levels: usize) -> ContextExpr {
        let mut expr = ContextExpr::True;
        for _ in 0..levels {
            // Wrap in AND where BOTH sides need evaluation (no short-circuit)
            // left=True, right=nested - both get evaluated, right recurses
            expr = ContextExpr::And(
                Box::new(ContextExpr::True),
                Box::new(expr)
            );
        }
        expr
    }

    let ctx = BTreeMap::new();
    
    // At MAX_EXPR_DEPTH levels, should succeed
    // (depth goes: 0 at root, then 1, 2, ..., MAX_EXPR_DEPTH for inner)
    let expr_ok = build_nested_and(MAX_EXPR_DEPTH);
    let result = expr_ok.evaluate(&ctx, 0);
    assert!(result.is_ok(), 
        "AND nested {} levels should succeed (depth 0..{})", 
        MAX_EXPR_DEPTH, MAX_EXPR_DEPTH);
    
    // At MAX_EXPR_DEPTH + 1 levels, should FAIL with ExpressionTooDeep
    // (depth would reach MAX_EXPR_DEPTH + 1 > MAX_EXPR_DEPTH)
    let expr_fail = build_nested_and(MAX_EXPR_DEPTH + 1);
    let result = expr_fail.evaluate(&ctx, 0);
    assert!(result.is_err(), 
        "AND nested {} levels should fail (depth would exceed {})", 
        MAX_EXPR_DEPTH + 1, MAX_EXPR_DEPTH);
}

/// Test that nested OR correctly tracks depth.
/// Similar to AND, but uses OR with values that don't short-circuit.
#[test]
fn kill_depth_increment_or_surgical() {
    fn build_nested_or(levels: usize) -> ContextExpr {
        let mut expr = ContextExpr::False;
        for _ in 0..levels {
            // Wrap in OR where left=False so right MUST be evaluated
            expr = ContextExpr::Or(
                Box::new(ContextExpr::False),
                Box::new(expr)
            );
        }
        expr
    }

    let ctx = BTreeMap::new();
    
    // At MAX_EXPR_DEPTH levels, should succeed
    let expr_ok = build_nested_or(MAX_EXPR_DEPTH);
    let result = expr_ok.evaluate(&ctx, 0);
    assert!(result.is_ok(), 
        "OR nested {} levels should succeed", MAX_EXPR_DEPTH);
    
    // At MAX_EXPR_DEPTH + 1 levels, should FAIL
    let expr_fail = build_nested_or(MAX_EXPR_DEPTH + 1);
    let result = expr_fail.evaluate(&ctx, 0);
    assert!(result.is_err(), 
        "OR nested {} levels should fail", MAX_EXPR_DEPTH + 1);
}

/// Test that the short-circuit path (left side of AND/OR) also tracks depth correctly.
/// This targets the depth + 1 in lines 193 and 202 (the left.evaluate calls).
#[test]
fn kill_depth_increment_left_branch() {
    // Build nesting on the LEFT side of AND (which gets evaluated first)
    fn build_left_nested_and(levels: usize) -> ContextExpr {
        let mut expr = ContextExpr::True;
        for _ in 0..levels {
            expr = ContextExpr::And(
                Box::new(expr),         // LEFT side is nested
                Box::new(ContextExpr::True)  // RIGHT side is leaf
            );
        }
        expr
    }

    let ctx = BTreeMap::new();
    
    // Should succeed at MAX_EXPR_DEPTH
    let expr_ok = build_left_nested_and(MAX_EXPR_DEPTH);
    assert!(expr_ok.evaluate(&ctx, 0).is_ok());
    
    // Should fail at MAX_EXPR_DEPTH + 1
    let expr_fail = build_left_nested_and(MAX_EXPR_DEPTH + 1);
    assert!(expr_fail.evaluate(&ctx, 0).is_err());
}

// ============================================================================
// KILL: > with >= in parse length check (line 261)
// If > becomes >=, input.len() == MAX_EXPR_LENGTH would be rejected
// ============================================================================

#[test]
fn kill_length_boundary_exact() {
    // Create a valid expression at exactly MAX_EXPR_LENGTH
    // "TRUE" padded with spaces to reach the limit
    let padding = MAX_EXPR_LENGTH - 4; // "TRUE" is 4 chars
    let input = format!("{:>width$}", "TRUE", width = MAX_EXPR_LENGTH);
    assert_eq!(input.len(), MAX_EXPR_LENGTH);
    
    // This should succeed (>= would reject it, > accepts it)
    let result = ContextExpr::parse(&input);
    // May fail for syntax but NOT for length
    // Actually, this has leading spaces which are valid
    assert!(result.is_ok(), "Exact MAX_EXPR_LENGTH should be accepted");
}

#[test]
fn kill_length_boundary_one_over() {
    let input = " ".repeat(MAX_EXPR_LENGTH + 1);
    let result = ContextExpr::parse(&input);
    assert!(result.is_err(), "One over MAX_EXPR_LENGTH must be rejected");
}

// ============================================================================
// KILL: < with <= and > with >= in compare_values (lines 279, 281)
// These need tests that distinguish strict from non-strict comparison
// ============================================================================

#[test]
fn kill_less_than_strict() {
    let mut ctx = BTreeMap::new();
    ctx.insert("val".to_string(), "b".to_string());
    
    // "b" < "b" should be false (LessThan is STRICT)
    let expr = ContextExpr::Compare {
        key: "val".to_string(),
        op: CompareOp::LessThan,
        value: "b".to_string(),
    };
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false, "b < b must be false");
    
    // "a" < "b" should be true
    ctx.insert("val".to_string(), "a".to_string());
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true, "a < b must be true");
}

#[test]
fn kill_greater_than_strict() {
    let mut ctx = BTreeMap::new();
    ctx.insert("val".to_string(), "b".to_string());
    
    // "b" > "b" should be false (GreaterThan is STRICT)
    let expr = ContextExpr::Compare {
        key: "val".to_string(),
        op: CompareOp::GreaterThan,
        value: "b".to_string(),
    };
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false, "b > b must be false");
    
    // "c" > "b" should be true
    ctx.insert("val".to_string(), "c".to_string());
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true, "c > b must be true");
}

// ============================================================================
// KILL: delete match arm '!' and '<' in tokenize (lines 337, 348)
// KILL: == with != in tokenize (lines 339, 350)
// ============================================================================

#[test]
fn kill_not_equal_operator() {
    // Test that != is properly tokenized and works
    let input = r#"role != "admin""#;
    let result = ContextExpr::parse(input);
    assert!(result.is_ok(), "!= must be tokenized correctly");
    
    let expr = result.unwrap();
    let mut ctx = BTreeMap::new();
    ctx.insert("role".to_string(), "user".to_string());
    
    // role != "admin" should be true when role is "user"
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    
    ctx.insert("role".to_string(), "admin".to_string());
    // role != "admin" should be false when role is "admin"
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false);
}

#[test]
fn kill_less_than_operator_tokenize() {
    // Test that < is properly tokenized
    let input = r#"age < "30""#;
    let result = ContextExpr::parse(input);
    assert!(result.is_ok(), "< must be tokenized correctly");
    
    let expr = result.unwrap();
    let mut ctx = BTreeMap::new();
    ctx.insert("age".to_string(), "25".to_string());
    
    // "25" < "30" lexicographically
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
}

#[test]
fn kill_less_than_or_equal_tokenize() {
    // Test <= is properly tokenized (two-char operator)
    let input = r#"age <= "30""#;
    let result = ContextExpr::parse(input);
    assert!(result.is_ok(), "<= must be tokenized correctly");
    
    let expr = result.unwrap();
    let mut ctx = BTreeMap::new();
    
    // Test equality case (the <= vs < distinction)
    ctx.insert("age".to_string(), "30".to_string());
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true, "30 <= 30 must be true");
}

#[test]
fn kill_greater_than_or_equal_tokenize() {
    // Test >= is properly tokenized
    let input = r#"age >= "30""#;
    let result = ContextExpr::parse(input);
    assert!(result.is_ok(), ">= must be tokenized correctly");
    
    let expr = result.unwrap();
    let mut ctx = BTreeMap::new();
    
    // Test equality case
    ctx.insert("age".to_string(), "30".to_string());
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true, "30 >= 30 must be true");
}

// ============================================================================
// KILL: escape sequence handling in string literals (lines 372-373)
// ============================================================================

#[test]
fn kill_escape_in_string() {
    // Test escaped quote inside string
    let input = r#"msg == "he said \"hello\"""#;
    let result = ContextExpr::parse(input);
    assert!(result.is_ok(), "Escaped quotes must work");
    
    let expr = result.unwrap();
    let mut ctx = BTreeMap::new();
    ctx.insert("msg".to_string(), r#"he said "hello""#.to_string());
    
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
}

#[test]
fn kill_escape_backslash() {
    // Test escaped backslash
    let input = r#"path == "c:\\folder""#;
    let result = ContextExpr::parse(input);
    assert!(result.is_ok(), "Escaped backslash must work");
    
    let expr = result.unwrap();
    let mut ctx = BTreeMap::new();
    ctx.insert("path".to_string(), r#"c:\folder"#.to_string());
    
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
}

// ============================================================================
// KILL: Parser::expect match guard (line 445)
// If `token == &expected` becomes `true`, expect() always succeeds,
// meaning wrong tokens are accepted (e.g., wrong closing paren).
// ============================================================================

#[test]
fn kill_expect_wrong_token() {
    // Test that mismatched parentheses are caught
    let input = "(TRUE"; 
    let result = ContextExpr::parse(input);
    assert!(result.is_err(), "Missing closing paren must fail");
    
    // Test unbalanced nested parens
    let input = "((TRUE)";
    let result = ContextExpr::parse(input);
    assert!(result.is_err(), "Unbalanced nested parens must fail");
}

/// Test that expect() correctly rejects wrong tokens.
/// The mutant makes expect() always return Ok(()), accepting any token.
/// This means "(TRUE AND FALSE" without closing paren would be accepted.
#[test]
fn kill_expect_token_mismatch_surgical() {
    // These should all fail because they're missing the closing paren
    let failing_cases = [
        "(TRUE",
        "((TRUE)",
        "(TRUE AND FALSE",
        "(TRUE OR (FALSE)",
        "((((TRUE))))",
    ];
    
    // Actually test cases that MUST fail
    for case in ["(TRUE", "((TRUE)", "(TRUE AND FALSE", "(TRUE OR (FALSE)"] {
        let result = ContextExpr::parse(case);
        assert!(result.is_err(), "'{}' must fail - unbalanced parens", case);
    }
    
    // And verify that balanced parens succeed and produce correct results
    let balanced = "(TRUE)";
    let result = ContextExpr::parse(balanced);
    assert!(result.is_ok(), "'{}' must succeed", balanced);
    let expr = result.unwrap();
    let ctx = BTreeMap::new();
    assert!(expr.evaluate(&ctx, 0).unwrap(), "(TRUE) must evaluate to true");
    
    // More complex balanced expression
    let balanced = "((TRUE AND FALSE))";
    let result = ContextExpr::parse(balanced);
    assert!(result.is_ok(), "'{}' must succeed", balanced);
    let expr = result.unwrap();
    assert!(!expr.evaluate(&ctx, 0).unwrap(), "((TRUE AND FALSE)) must be false");
}

// ============================================================================
// KILL: delete match arms for comparison operators in parse_primary (532-535)
// ============================================================================

#[test]
fn kill_all_comparison_operators() {
    let ops = [
        ("==", CompareOp::Equal),
        ("!=", CompareOp::NotEqual),
        ("<", CompareOp::LessThan),
        ("<=", CompareOp::LessThanOrEqual),
        (">", CompareOp::GreaterThan),
        (">=", CompareOp::GreaterThanOrEqual),
    ];
    
    for (op_str, _expected_op) in ops {
        let input = format!(r#"key {} "value""#, op_str);
        let result = ContextExpr::parse(&input);
        assert!(result.is_ok(), "Operator {} must parse correctly", op_str);
    }
}

#[test]
fn kill_identifier_as_value() {
    // Test unquoted identifier as value (line 548)
    let input = "role == admin";  // admin without quotes
    let result = ContextExpr::parse(input);
    assert!(result.is_ok(), "Unquoted value must work");
    
    let expr = result.unwrap();
    let mut ctx = BTreeMap::new();
    ctx.insert("role".to_string(), "admin".to_string());
    
    assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
}

// ============================================================================
// KILL: Display for CompareOp (line 135) - this is cosmetic but we test it
// ============================================================================

#[test]
fn kill_compare_op_display() {
    // While Display is typically for formatting, we should verify it works
    assert_eq!(format!("{}", CompareOp::Equal), "==");
    assert_eq!(format!("{}", CompareOp::NotEqual), "!=");
    assert_eq!(format!("{}", CompareOp::LessThan), "<");
    assert_eq!(format!("{}", CompareOp::LessThanOrEqual), "<=");
    assert_eq!(format!("{}", CompareOp::GreaterThan), ">");
    assert_eq!(format!("{}", CompareOp::GreaterThanOrEqual), ">=");
}
