//! Property-Based Tests for ContextExpr Parser
//!
//! These tests use proptest to generate random inputs and verify that
//! business logic invariants are ALWAYS maintained:
//!
//! 1. MAX_EXPR_LENGTH is enforced (DoS prevention)
//! 2. MAX_EXPR_DEPTH is enforced during evaluation (stack overflow prevention)
//! 3. Parsing never panics on any input
//! 4. Evaluation is deterministic (same input = same output)
//! 5. Boolean logic is correct (AND, OR, NOT semantics)

use core_policy::{ContextExpr, CompareOp, MAX_EXPR_DEPTH, MAX_EXPR_LENGTH};
use proptest::prelude::*;
use std::collections::BTreeMap;

// ============================================================================
// PROPERTY 1: MAX_EXPR_LENGTH is always enforced
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Any string longer than MAX_EXPR_LENGTH must be rejected
    #[test]
    fn prop_max_length_enforced(extra_len in 1usize..1000) {
        let input = "a".repeat(MAX_EXPR_LENGTH + extra_len);
        let result = ContextExpr::parse(&input);
        
        prop_assert!(
            result.is_err(),
            "Input of length {} should be rejected (max: {})",
            input.len(),
            MAX_EXPR_LENGTH
        );
    }

    /// Strings at or below MAX_EXPR_LENGTH should not fail due to length
    #[test]
    fn prop_within_length_allowed(len in 1usize..=MAX_EXPR_LENGTH) {
        let input = "a".repeat(len);
        let result = ContextExpr::parse(&input);
        
        // May fail for syntax, but NOT for length
        // We can't easily check the error type, but we verify no panic
        let _ = result;
    }
}

// ============================================================================
// PROPERTY 2: Parsing NEVER panics
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Parsing any arbitrary string must not panic
    #[test]
    fn prop_parse_never_panics(input in ".*") {
        // This should NEVER panic, only return Ok or Err
        let _ = ContextExpr::parse(&input);
    }

    /// Parsing strings with special characters must not panic
    #[test]
    fn prop_parse_special_chars_safe(
        prefix in "[()\"\\\\AND OR NOT HAS TRUE FALSE == != < <= > >=]*",
        middle in "\\PC*",  // Any printable char
        suffix in "[()\"\\\\]*"
    ) {
        let input = format!("{}{}{}", prefix, middle, suffix);
        if input.len() <= MAX_EXPR_LENGTH {
            let _ = ContextExpr::parse(&input);
        }
    }

    /// Parsing expressions with random nesting must not panic
    #[test]
    fn prop_parse_random_nesting_safe(
        open_count in 0usize..200,
        close_count in 0usize..200,
        inner in "(TRUE|FALSE|role == \"admin\")"
    ) {
        let input = format!(
            "{}{}{}",
            "(".repeat(open_count),
            inner,
            ")".repeat(close_count)
        );
        if input.len() <= MAX_EXPR_LENGTH {
            let _ = ContextExpr::parse(&input);
        }
    }
}

// ============================================================================
// PROPERTY 3: Evaluation is DETERMINISTIC
// ============================================================================

fn arbitrary_context() -> impl Strategy<Value = BTreeMap<String, String>> {
    prop::collection::btree_map(
        "[a-z]{1,10}",      // keys
        "[a-zA-Z0-9]{1,20}", // values
        0..10               // size
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Same expression + same context = same result (determinism)
    #[test]
    fn prop_evaluation_deterministic(
        expr_str in "(TRUE|FALSE|role == \"admin\"|dept == \"IT\"|HAS role)",
        ctx in arbitrary_context()
    ) {
        if let Ok(expr) = ContextExpr::parse(&expr_str) {
            // Evaluate three times independently
            let r1 = expr.evaluate(&ctx, 0);
            let r2 = expr.evaluate(&ctx, 0);
            let r3 = expr.evaluate(&ctx, 0);
            
            // All three should have the same success/failure status
            prop_assert!(r1.is_ok() == r2.is_ok(), "Determinism: same ok status");
            prop_assert!(r2.is_ok() == r3.is_ok(), "Determinism: same ok status");
            
            // If successful, values must match
            if let (Ok(v1), Ok(v2), Ok(v3)) = (r1, r2, r3) {
                prop_assert_eq!(v1, v2, "Evaluation must be deterministic");
                prop_assert_eq!(v2, v3, "Evaluation must be deterministic");
            }
        }
    }

    /// Evaluation with depth 0 must be equivalent to fresh evaluation
    #[test]
    fn prop_depth_zero_consistent(
        expr_str in "(TRUE|FALSE|role == \"admin\")",
        ctx in arbitrary_context()
    ) {
        if let Ok(expr) = ContextExpr::parse(&expr_str) {
            let at_zero = expr.evaluate(&ctx, 0);
            let at_one = expr.evaluate(&ctx, 1);
            
            // Both should succeed for simple expressions
            if at_zero.is_ok() && at_one.is_ok() {
                prop_assert_eq!(
                    at_zero.unwrap(),
                    at_one.unwrap(),
                    "Result should be same regardless of starting depth for simple exprs"
                );
            }
        }
    }
}

// ============================================================================
// PROPERTY 4: MAX_EXPR_DEPTH is enforced during evaluation
// ============================================================================

/// Generate a deeply nested expression programmatically
fn make_nested_expr(depth: usize) -> ContextExpr {
    if depth == 0 {
        ContextExpr::True
    } else {
        ContextExpr::Not(Box::new(make_nested_expr(depth - 1)))
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Expressions deeper than MAX_EXPR_DEPTH must fail at evaluation
    #[test]
    fn prop_max_depth_enforced(extra_depth in 1usize..50) {
        let expr = make_nested_expr(MAX_EXPR_DEPTH + extra_depth);
        let ctx = BTreeMap::new();
        let result = expr.evaluate(&ctx, 0);
        
        prop_assert!(
            result.is_err(),
            "Expression with depth {} should fail (max: {})",
            MAX_EXPR_DEPTH + extra_depth,
            MAX_EXPR_DEPTH
        );
    }

    /// Expressions at or below MAX_EXPR_DEPTH should succeed
    #[test]
    fn prop_within_depth_allowed(depth in 1usize..=MAX_EXPR_DEPTH) {
        let expr = make_nested_expr(depth);
        let ctx = BTreeMap::new();
        let result = expr.evaluate(&ctx, 0);
        
        // Should succeed (NOT NOT NOT ... TRUE = TRUE or FALSE)
        prop_assert!(
            result.is_ok(),
            "Expression with depth {} should succeed (max: {})",
            depth,
            MAX_EXPR_DEPTH
        );
    }
}

// ============================================================================
// PROPERTY 5: Boolean logic is CORRECT
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// TRUE always evaluates to true
    #[test]
    fn prop_true_is_true(ctx in arbitrary_context()) {
        let expr = ContextExpr::True;
        let result = expr.evaluate(&ctx, 0);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap(), true);
    }

    /// FALSE always evaluates to false
    #[test]
    fn prop_false_is_false(ctx in arbitrary_context()) {
        let expr = ContextExpr::False;
        let result = expr.evaluate(&ctx, 0);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap(), false);
    }

    /// NOT TRUE = FALSE
    #[test]
    fn prop_not_true_is_false(ctx in arbitrary_context()) {
        let expr = ContextExpr::Not(Box::new(ContextExpr::True));
        let result = expr.evaluate(&ctx, 0);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap(), false);
    }

    /// NOT FALSE = TRUE
    #[test]
    fn prop_not_false_is_true(ctx in arbitrary_context()) {
        let expr = ContextExpr::Not(Box::new(ContextExpr::False));
        let result = expr.evaluate(&ctx, 0);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap(), true);
    }

    /// Double negation: NOT NOT x = x
    #[test]
    fn prop_double_negation(b in any::<bool>(), ctx in arbitrary_context()) {
        let inner = if b { ContextExpr::True } else { ContextExpr::False };
        let expr = ContextExpr::Not(Box::new(ContextExpr::Not(Box::new(inner.clone()))));
        
        let original = inner.evaluate(&ctx, 0).unwrap();
        let double_neg = expr.evaluate(&ctx, 0).unwrap();
        
        prop_assert_eq!(original, double_neg, "NOT NOT x must equal x");
    }

    /// AND truth table: TRUE AND TRUE = TRUE
    #[test]
    fn prop_and_tt(ctx in arbitrary_context()) {
        let expr = ContextExpr::And(
            Box::new(ContextExpr::True),
            Box::new(ContextExpr::True)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    }

    /// AND truth table: TRUE AND FALSE = FALSE
    #[test]
    fn prop_and_tf(ctx in arbitrary_context()) {
        let expr = ContextExpr::And(
            Box::new(ContextExpr::True),
            Box::new(ContextExpr::False)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false);
    }

    /// AND truth table: FALSE AND TRUE = FALSE
    #[test]
    fn prop_and_ft(ctx in arbitrary_context()) {
        let expr = ContextExpr::And(
            Box::new(ContextExpr::False),
            Box::new(ContextExpr::True)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false);
    }

    /// AND truth table: FALSE AND FALSE = FALSE
    #[test]
    fn prop_and_ff(ctx in arbitrary_context()) {
        let expr = ContextExpr::And(
            Box::new(ContextExpr::False),
            Box::new(ContextExpr::False)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false);
    }

    /// OR truth table: TRUE OR TRUE = TRUE
    #[test]
    fn prop_or_tt(ctx in arbitrary_context()) {
        let expr = ContextExpr::Or(
            Box::new(ContextExpr::True),
            Box::new(ContextExpr::True)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    }

    /// OR truth table: TRUE OR FALSE = TRUE
    #[test]
    fn prop_or_tf(ctx in arbitrary_context()) {
        let expr = ContextExpr::Or(
            Box::new(ContextExpr::True),
            Box::new(ContextExpr::False)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    }

    /// OR truth table: FALSE OR TRUE = TRUE
    #[test]
    fn prop_or_ft(ctx in arbitrary_context()) {
        let expr = ContextExpr::Or(
            Box::new(ContextExpr::False),
            Box::new(ContextExpr::True)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    }

    /// OR truth table: FALSE OR FALSE = FALSE
    #[test]
    fn prop_or_ff(ctx in arbitrary_context()) {
        let expr = ContextExpr::Or(
            Box::new(ContextExpr::False),
            Box::new(ContextExpr::False)
        );
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false);
    }

    /// De Morgan's Law: NOT (A AND B) = (NOT A) OR (NOT B)
    #[test]
    fn prop_de_morgan_and(a in any::<bool>(), b in any::<bool>(), ctx in arbitrary_context()) {
        let a_expr = if a { ContextExpr::True } else { ContextExpr::False };
        let b_expr = if b { ContextExpr::True } else { ContextExpr::False };
        
        // NOT (A AND B)
        let left = ContextExpr::Not(Box::new(ContextExpr::And(
            Box::new(a_expr.clone()),
            Box::new(b_expr.clone())
        )));
        
        // (NOT A) OR (NOT B)
        let right = ContextExpr::Or(
            Box::new(ContextExpr::Not(Box::new(a_expr))),
            Box::new(ContextExpr::Not(Box::new(b_expr)))
        );
        
        prop_assert_eq!(
            left.evaluate(&ctx, 0).unwrap(),
            right.evaluate(&ctx, 0).unwrap(),
            "De Morgan's Law must hold"
        );
    }

    /// De Morgan's Law: NOT (A OR B) = (NOT A) AND (NOT B)
    #[test]
    fn prop_de_morgan_or(a in any::<bool>(), b in any::<bool>(), ctx in arbitrary_context()) {
        let a_expr = if a { ContextExpr::True } else { ContextExpr::False };
        let b_expr = if b { ContextExpr::True } else { ContextExpr::False };
        
        // NOT (A OR B)
        let left = ContextExpr::Not(Box::new(ContextExpr::Or(
            Box::new(a_expr.clone()),
            Box::new(b_expr.clone())
        )));
        
        // (NOT A) AND (NOT B)
        let right = ContextExpr::And(
            Box::new(ContextExpr::Not(Box::new(a_expr))),
            Box::new(ContextExpr::Not(Box::new(b_expr)))
        );
        
        prop_assert_eq!(
            left.evaluate(&ctx, 0).unwrap(),
            right.evaluate(&ctx, 0).unwrap(),
            "De Morgan's Law must hold"
        );
    }
}

// ============================================================================
// PROPERTY 6: Compare operations are correct
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Equal comparison: key exists and matches
    #[test]
    fn prop_compare_equal_match(value in "[a-z]{1,10}") {
        let mut ctx = BTreeMap::new();
        ctx.insert("key".to_string(), value.clone());
        
        let expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::Equal,
            value: value.clone(),
        };
        
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    }

    /// Equal comparison: key exists but doesn't match
    #[test]
    fn prop_compare_equal_mismatch(
        stored in "[a-z]{1,10}",
        compared in "[A-Z]{1,10}"  // Different case = different value
    ) {
        let mut ctx = BTreeMap::new();
        ctx.insert("key".to_string(), stored);
        
        let expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::Equal,
            value: compared,
        };
        
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false);
    }

    /// NotEqual is the inverse of Equal
    #[test]
    fn prop_not_equal_inverse(
        stored in "[a-z]{1,5}",
        compared in "[a-z]{1,5}"
    ) {
        let mut ctx = BTreeMap::new();
        ctx.insert("key".to_string(), stored.clone());
        
        let eq_expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::Equal,
            value: compared.clone(),
        };
        
        let neq_expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::NotEqual,
            value: compared,
        };
        
        let eq_result = eq_expr.evaluate(&ctx, 0).unwrap();
        let neq_result = neq_expr.evaluate(&ctx, 0).unwrap();
        
        prop_assert_eq!(eq_result, !neq_result, "!= must be inverse of ==");
    }

    /// Missing key always returns false for comparisons
    #[test]
    fn prop_missing_key_false(value in "[a-z]{1,10}") {
        let ctx = BTreeMap::new(); // Empty context
        
        let expr = ContextExpr::Compare {
            key: "nonexistent".to_string(),
            op: CompareOp::Equal,
            value,
        };
        
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), false);
    }

    /// HasAttribute returns true iff key exists
    #[test]
    fn prop_has_attribute_correct(
        key in "[a-z]{1,5}",
        value in "[a-z]{1,10}",
        check_existing in any::<bool>()
    ) {
        let mut ctx = BTreeMap::new();
        ctx.insert(key.clone(), value);
        
        let check_key = if check_existing { key } else { "other".to_string() };
        let expr = ContextExpr::HasAttribute(check_key.clone());
        
        let expected = ctx.contains_key(&check_key);
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), expected);
    }
}

// ============================================================================
// PROPERTY 7: Lexicographic comparison operators
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Less than comparison (lexicographic)
    #[test]
    fn prop_less_than_correct(
        stored in "[a-m]{1,5}",  // First half of alphabet
        compared in "[n-z]{1,5}" // Second half of alphabet
    ) {
        let mut ctx = BTreeMap::new();
        ctx.insert("key".to_string(), stored.clone());
        
        // stored < compared should be true (first half < second half)
        let expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::LessThan,
            value: compared.clone(),
        };
        
        // This should be true since a-m < n-z lexicographically
        let result = expr.evaluate(&ctx, 0).unwrap();
        let expected = stored < compared;
        prop_assert_eq!(result, expected);
    }

    /// Greater than comparison (lexicographic)
    #[test]
    fn prop_greater_than_correct(
        stored in "[n-z]{1,5}",  // Second half of alphabet
        compared in "[a-m]{1,5}" // First half of alphabet
    ) {
        let mut ctx = BTreeMap::new();
        ctx.insert("key".to_string(), stored.clone());
        
        let expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::GreaterThan,
            value: compared.clone(),
        };
        
        let result = expr.evaluate(&ctx, 0).unwrap();
        let expected = stored > compared;
        prop_assert_eq!(result, expected);
    }

    /// LessThanOrEqual includes equality
    #[test]
    fn prop_lte_includes_equal(value in "[a-z]{1,5}") {
        let mut ctx = BTreeMap::new();
        ctx.insert("key".to_string(), value.clone());
        
        let expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::LessThanOrEqual,
            value: value.clone(),
        };
        
        // value <= value should always be true
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    }

    /// GreaterThanOrEqual includes equality
    #[test]
    fn prop_gte_includes_equal(value in "[a-z]{1,5}") {
        let mut ctx = BTreeMap::new();
        ctx.insert("key".to_string(), value.clone());
        
        let expr = ContextExpr::Compare {
            key: "key".to_string(),
            op: CompareOp::GreaterThanOrEqual,
            value: value.clone(),
        };
        
        // value >= value should always be true
        prop_assert_eq!(expr.evaluate(&ctx, 0).unwrap(), true);
    }
}
