//! Fuzz target for ContextExpr parser (Anti-Stack Overflow)
//!
//! This target bombards the parser with malicious input strings, specifically:
//! - Deep nesting: (((((...))))) patterns
//! - Long expressions with many operators
//! - Malformed input with unbalanced parentheses
//! - Random binary data interpreted as strings
//!
//! The goal is to ensure the parser handles all input gracefully without:
//! - Stack overflow (the primary concern)
//! - Panics or crashes
//! - Excessive memory allocation (DoS)

#![no_main]

use libfuzzer_sys::fuzz_target;
use core_policy::ContextExpr;
use std::collections::BTreeMap;

fuzz_target!(|data: &str| {
    // Primary test: ContextExpr::parse should NEVER panic on any input
    // It must return Ok or Err, but never crash
    let parse_result = ContextExpr::parse(data);

    // If parsing succeeds, verify the expression can be evaluated safely
    if let Ok(expr) = parse_result {
        // Create a minimal context for evaluation
        let mut context: BTreeMap<String, String> = BTreeMap::new();
        context.insert("role".to_string(), "user".to_string());
        context.insert("department".to_string(), "engineering".to_string());
        context.insert("level".to_string(), "5".to_string());

        // Evaluation must also never panic, even on deeply nested expressions
        // The depth parameter starts at 0; MAX_EXPR_DEPTH should protect us
        let eval_result = expr.evaluate(&context, 0);

        // If evaluation succeeds, verify it returns a valid boolean
        if let Ok(result) = eval_result {
            // Result is a bool, nothing special to check
            let _ = result;
        }
        // If evaluation fails with ExpressionTooDeep, that's expected behavior
        // Other errors are also acceptable - we just verify no panics
    }
});

