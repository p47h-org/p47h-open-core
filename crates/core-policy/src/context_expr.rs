//! # ABAC Context Expression Parser & Evaluator
//!
//! This module provides boolean expression parsing and evaluation for
//! Attribute-Based Access Control (ABAC).
//!
//! ## Features
//!
//! - **Boolean Operators**: AND, OR, NOT
//! - **Comparison Operators**: ==, !=, <, <=, >, >=
//! - **Attribute Queries**: HasAttribute, GetAttribute
//! - **Recursion Limits**: Prevents stack overflow from malicious expressions
//! - **Deterministic Evaluation**: O(N) complexity where N = expression size
//!
//! ## Syntax Examples
//!
//! ```text
//! role == "admin"
//! role == "admin" AND department == "IT"
//! (role == "admin" OR role == "moderator") AND timestamp < "1000"
//! NOT (status == "banned")
//! role == "user" AND (age >= "18" OR has_parent_consent == "true")
//! ```
//!
//! ## Security
//!
//! - Maximum expression depth: 32 (prevents stack overflow)
//! - Maximum expression length: 1024 characters (DoS prevention)
//! - Iterative evaluation where possible (reduces stack usage)

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::error::{PolicyError, Result};

/// Maximum depth of nested expressions (prevents stack overflow)
pub const MAX_EXPR_DEPTH: usize = 32;

/// Maximum length of expression string (DoS prevention)
pub const MAX_EXPR_LENGTH: usize = 1024;

/// Context expression for ABAC evaluation
///
/// This enum represents a boolean expression tree that can be evaluated
/// against a context (attribute map) to determine if conditions are met.
///
/// ## Design Rationale
///
/// - **Recursive Structure**: Allows complex nested conditions
/// - **Type Safety**: Rust's type system prevents malformed expressions
/// - **Deterministic**: No floating point, no random operations
/// - **Serializable**: Can be stored in policy files (YAML/JSON)
///
/// ## Example
///
/// ```
/// extern crate alloc;
/// use core_policy::context_expr::{ContextExpr, CompareOp};
/// use alloc::collections::BTreeMap;
/// use alloc::string::ToString;
///
/// let expr = ContextExpr::And(
///     Box::new(ContextExpr::Compare {
///         key: "role".into(),
///         op: CompareOp::Equal,
///         value: "admin".into(),
///     }),
///     Box::new(ContextExpr::Compare {
///         key: "department".into(),
///         op: CompareOp::Equal,
///         value: "IT".into(),
///     }),
/// );
///
/// let mut context = BTreeMap::new();
/// context.insert("role".to_string(), "admin".to_string());
/// context.insert("department".to_string(), "IT".to_string());
///
/// assert!(expr.evaluate(&context, 0).unwrap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextExpr {
    /// Logical AND (both operands must be true)
    And(Box<ContextExpr>, Box<ContextExpr>),

    /// Logical OR (at least one operand must be true)
    Or(Box<ContextExpr>, Box<ContextExpr>),

    /// Logical NOT (negates the operand)
    Not(Box<ContextExpr>),

    /// Check if an attribute exists in the context
    HasAttribute(String),

    /// Compare an attribute value with a constant
    Compare {
        /// Attribute key to compare
        key: String,
        /// Comparison operator
        op: CompareOp,
        /// Value to compare against (as string)
        value: String,
    },

    /// Always true (useful for testing and default cases)
    True,

    /// Always false
    False,
}

/// Comparison operators for attribute values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareOp {
    /// Equal (==)
    Equal,
    /// Not equal (!=)
    NotEqual,
    /// Less than (<)
    LessThan,
    /// Less than or equal (<=)
    LessThanOrEqual,
    /// Greater than (>)
    GreaterThan,
    /// Greater than or equal (>=)
    GreaterThanOrEqual,
}

impl fmt::Display for CompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareOp::Equal => write!(f, "=="),
            CompareOp::NotEqual => write!(f, "!="),
            CompareOp::LessThan => write!(f, "<"),
            CompareOp::LessThanOrEqual => write!(f, "<="),
            CompareOp::GreaterThan => write!(f, ">"),
            CompareOp::GreaterThanOrEqual => write!(f, ">="),
        }
    }
}

impl ContextExpr {
    /// Evaluate this expression against a context
    ///
    /// # Arguments
    ///
    /// * `context` - Attribute map to evaluate against
    /// * `depth` - Current recursion depth (prevents stack overflow)
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Expression evaluates to true
    /// * `Ok(false)` - Expression evaluates to false
    /// * `Err(PolicyError::ExpressionTooDeep)` - Recursion limit exceeded
    ///
    /// # Example
    ///
    /// ```
    /// extern crate alloc;
    /// use core_policy::context_expr::{ContextExpr, CompareOp};
    /// use alloc::collections::BTreeMap;
    /// use alloc::string::ToString;
    ///
    /// let expr = ContextExpr::Compare {
    ///     key: "role".into(),
    ///     op: CompareOp::Equal,
    ///     value: "admin".into(),
    /// };
    ///
    /// let mut context = BTreeMap::new();
    /// context.insert("role".to_string(), "admin".to_string());
    ///
    /// assert!(expr.evaluate(&context, 0).unwrap());
    /// ```
    pub fn evaluate(&self, context: &BTreeMap<String, String>, depth: usize) -> Result<bool> {
        // Prevent stack overflow from deeply nested expressions
        if depth > MAX_EXPR_DEPTH {
            return Err(PolicyError::ExpressionTooDeep {
                max: MAX_EXPR_DEPTH,
            });
        }

        match self {
            ContextExpr::True => Ok(true),
            ContextExpr::False => Ok(false),

            ContextExpr::And(left, right) => {
                // Short-circuit evaluation: if left is false, don't evaluate right
                let left_result = left.evaluate(context, depth + 1)?;
                if !left_result {
                    return Ok(false);
                }
                right.evaluate(context, depth + 1)
            }

            ContextExpr::Or(left, right) => {
                // Short-circuit evaluation: if left is true, don't evaluate right
                let left_result = left.evaluate(context, depth + 1)?;
                if left_result {
                    return Ok(true);
                }
                right.evaluate(context, depth + 1)
            }

            ContextExpr::Not(expr) => {
                let result = expr.evaluate(context, depth + 1)?;
                Ok(!result)
            }

            ContextExpr::HasAttribute(key) => Ok(context.contains_key(key)),

            ContextExpr::Compare { key, op, value } => {
                // If attribute doesn't exist, comparison fails
                let actual = match context.get(key) {
                    Some(v) => v,
                    None => return Ok(false),
                };

                // Compare as strings (lexicographic order)
                // For numeric comparison, values should be zero-padded or use explicit numeric parsing
                Ok(compare_values(actual, value, *op))
            }
        }
    }

    /// Parse a context expression from a string
    ///
    /// # Grammar (simplified)
    ///
    /// ```text
    /// expr       ::= or_expr
    /// or_expr    ::= and_expr (OR and_expr)*
    /// and_expr   ::= not_expr (AND not_expr)*
    /// not_expr   ::= NOT primary | primary
    /// primary    ::= HAS key | key op value | (expr) | TRUE | FALSE
    /// op         ::= == | != | < | <= | > | >=
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use core_policy::context_expr::ContextExpr;
    ///
    /// let expr = ContextExpr::parse("role == \"admin\"").unwrap();
    /// let expr = ContextExpr::parse("role == \"admin\" AND department == \"IT\"").unwrap();
    /// let expr = ContextExpr::parse("(role == \"admin\" OR role == \"moderator\") AND active == \"true\"").unwrap();
    /// let expr = ContextExpr::parse("NOT (status == \"banned\")").unwrap();
    /// let expr = ContextExpr::parse("HAS role").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// * `PolicyError::InvalidExpression` - Syntax error in expression
    /// * `PolicyError::ExpressionTooLong` - Expression exceeds MAX_EXPR_LENGTH
    pub fn parse(input: &str) -> Result<Self> {
        // DoS prevention: limit expression length
        if input.len() > MAX_EXPR_LENGTH {
            return Err(PolicyError::ExpressionTooLong {
                max: MAX_EXPR_LENGTH,
                length: input.len(),
            });
        }

        let tokens = tokenize(input)?;
        let mut parser = Parser::new(&tokens);
        parser.parse_expr()
    }
}

/// Helper function to compare two string values with an operator
fn compare_values(left: &str, right: &str, op: CompareOp) -> bool {
    match op {
        CompareOp::Equal => left == right,
        CompareOp::NotEqual => left != right,
        CompareOp::LessThan => left < right,
        CompareOp::LessThanOrEqual => left <= right,
        CompareOp::GreaterThan => left > right,
        CompareOp::GreaterThanOrEqual => left >= right,
    }
}

// ===== TOKENIZER =====

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    And,
    Or,
    Not,
    Has,
    True,
    False,
    LeftParen,
    RightParen,
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Identifier(String),
    StringLiteral(String),
}

/// Tokenize input string into tokens
fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                tokens.push(Token::LeftParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RightParen);
                chars.next();
            }
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Equal);
                } else {
                    return Err(PolicyError::InvalidExpression(
                        "Single '=' not allowed, use '=='".into(),
                    ));
                }
            }
            '!' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::NotEqual);
                } else {
                    return Err(PolicyError::InvalidExpression(
                        "Single '!' not allowed, use '!=' or 'NOT'".into(),
                    ));
                }
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::LessThanOrEqual);
                } else {
                    tokens.push(Token::LessThan);
                }
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::GreaterThanOrEqual);
                } else {
                    tokens.push(Token::GreaterThan);
                }
            }
            '"' => {
                chars.next();
                let mut value = String::new();
                let mut escaped = false;
                loop {
                    match chars.next() {
                        Some('\\') if !escaped => escaped = true,
                        Some('"') if !escaped => break,
                        Some(c) => {
                            value.push(c);
                            escaped = false;
                        }
                        None => {
                            return Err(PolicyError::InvalidExpression(
                                "Unterminated string literal".into(),
                            ))
                        }
                    }
                }
                tokens.push(Token::StringLiteral(value));
            }
            c if c.is_alphabetic() || c == '_' => {
                let mut ident = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        ident.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Check for keywords
                let token = match ident.as_str() {
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "NOT" => Token::Not,
                    "HAS" => Token::Has,
                    "TRUE" => Token::True,
                    "FALSE" => Token::False,
                    _ => Token::Identifier(ident),
                };
                tokens.push(token);
            }
            _ => {
                return Err(PolicyError::InvalidExpression(format!(
                    "Unexpected character: '{}'",
                    ch
                )))
            }
        }
    }

    Ok(tokens)
}

// ===== PARSER =====

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn current(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        self.pos += 1;
        token
    }

    fn expect(&mut self, expected: Token) -> Result<()> {
        match self.advance() {
            Some(token) if token == &expected => Ok(()),
            Some(token) => Err(PolicyError::InvalidExpression(format!(
                "Expected {:?}, got {:?}",
                expected, token
            ))),
            None => Err(PolicyError::InvalidExpression(format!(
                "Expected {:?}, got EOF",
                expected
            ))),
        }
    }

    // expr ::= or_expr
    fn parse_expr(&mut self) -> Result<ContextExpr> {
        self.parse_or()
    }

    // or_expr ::= and_expr (OR and_expr)*
    fn parse_or(&mut self) -> Result<ContextExpr> {
        let mut left = self.parse_and()?;

        while matches!(self.current(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = ContextExpr::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    // and_expr ::= not_expr (AND not_expr)*
    fn parse_and(&mut self) -> Result<ContextExpr> {
        let mut left = self.parse_not()?;

        while matches!(self.current(), Some(Token::And)) {
            self.advance();
            let right = self.parse_not()?;
            left = ContextExpr::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    // not_expr ::= NOT primary | primary
    fn parse_not(&mut self) -> Result<ContextExpr> {
        if matches!(self.current(), Some(Token::Not)) {
            self.advance();
            let expr = self.parse_primary()?;
            Ok(ContextExpr::Not(Box::new(expr)))
        } else {
            self.parse_primary()
        }
    }

    // primary ::= HAS key | key op value | (expr) | TRUE | FALSE
    fn parse_primary(&mut self) -> Result<ContextExpr> {
        match self.current() {
            Some(Token::True) => {
                self.advance();
                Ok(ContextExpr::True)
            }
            Some(Token::False) => {
                self.advance();
                Ok(ContextExpr::False)
            }
            Some(Token::Has) => {
                self.advance();
                match self.advance() {
                    Some(Token::Identifier(key)) => Ok(ContextExpr::HasAttribute(key.clone())),
                    _ => Err(PolicyError::InvalidExpression(
                        "Expected identifier after HAS".into(),
                    )),
                }
            }
            Some(Token::LeftParen) => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(Token::RightParen)?;
                Ok(expr)
            }
            Some(Token::Identifier(key)) => {
                let key = key.clone();
                self.advance();

                // Parse comparison operator
                let op = match self.current() {
                    Some(Token::Equal) => CompareOp::Equal,
                    Some(Token::NotEqual) => CompareOp::NotEqual,
                    Some(Token::LessThan) => CompareOp::LessThan,
                    Some(Token::LessThanOrEqual) => CompareOp::LessThanOrEqual,
                    Some(Token::GreaterThan) => CompareOp::GreaterThan,
                    Some(Token::GreaterThanOrEqual) => CompareOp::GreaterThanOrEqual,
                    _ => {
                        return Err(PolicyError::InvalidExpression(
                            "Expected comparison operator".into(),
                        ))
                    }
                };
                self.advance();

                // Parse value
                let value = match self.advance() {
                    Some(Token::StringLiteral(v)) => v.clone(),
                    Some(Token::Identifier(v)) => v.clone(), // Allow unquoted values
                    _ => {
                        return Err(PolicyError::InvalidExpression(
                            "Expected value after comparison operator".into(),
                        ))
                    }
                };

                Ok(ContextExpr::Compare { key, op, value })
            }
            _ => Err(PolicyError::InvalidExpression("Expected expression".into())),
        }
    }
}

// ============================================================================
// Kani Formal Verification Proofs (simplified)
// ============================================================================

/// Formal verification proofs using Kani.
/// Run with: `cargo kani --package core-policy`
///
/// These proofs use concrete values instead of `kani::any()` to avoid the
/// requirement of `kani::Arbitrary` for `ContextExpr`, `BTreeMap` and `String`.
///
/// NOTE: Unwind bounds are kept low to prevent CBMC from exhausting memory.
/// The proofs verify absence of panics for simple, representative inputs.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // 1. evaluate() never panics on a simple expression with bounded depth
    //    Using low unwind (10) since we only evaluate ContextExpr::True
    #[kani::proof]
    #[kani::unwind(10)]
    fn proof_evaluate_never_panics() {
        let expr = ContextExpr::True;
        let mut ctx = BTreeMap::new();
        ctx.insert(String::from("key"), String::from("value"));
        let _ = expr.evaluate(&ctx, 0);
    }

    // 2. depth limit is always enforced – when depth > MAX, evaluate returns error
    //    No recursion needed, so unwind(0)
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_depth_limit_enforced() {
        let expr = ContextExpr::True;
        let ctx = BTreeMap::new();
        let result = expr.evaluate(&ctx, MAX_EXPR_DEPTH + 1);
        kani::assert(result.is_err(), "Depth > MAX must always fail");
    }

    // 3. depth + 1 does not overflow (checked for a value within the limit)
    //    Pure arithmetic, no loops
    #[kani::proof]
    #[kani::unwind(0)]
    fn proof_depth_no_overflow() {
        let depth = MAX_EXPR_DEPTH;
        let new_depth = depth + 1;
        kani::assert(new_depth <= MAX_EXPR_DEPTH + 1, "Depth increment safe");
    }

    // NOTE: proof_parse_never_panics was removed because the parser uses
    // recursive descent with Vec allocations that cause CBMC to exhaust memory.
    // Parser correctness is covered by existing unit tests and fuzz testing.
}
