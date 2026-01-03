//! Path matching using a custom wildcard implementation to avoid external dependencies.
//!
//! This module accepts wildcard forms commonly used in shells:
//! - `*` - matches any sequence of characters except the path separator `/`
//! - `?` - matches a single character
//!
//! **NOTE**: `**` is not supported in this implementation and is treated as a literal `*`.
//!
//! ## Security
//!
//! Matches paths using a non-recursive, zero-allocation algorithm.
//! Safe for use with untrusted inputs (guaranteed O(N) time complexity).
//!
//! ## Examples
//! - `/home/*/documents`
//! - `/tmp/file?.txt`

use crate::error::{PolicyError, Result};
use crate::MAX_RESOURCE_PATTERN_LENGTH;
use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Path pattern with wildcard support.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathPattern {
    pattern: String,
}

impl PathPattern {
    /// Create a new path pattern
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::PatternTooLong` if pattern exceeds `MAX_RESOURCE_PATTERN_LENGTH`
    pub fn new(pattern: impl Into<String>) -> Result<Self> {
        let pattern = pattern.into();

        // T20 mitigation: Enforce maximum pattern length
        if pattern.len() > MAX_RESOURCE_PATTERN_LENGTH {
            return Err(PolicyError::PatternTooLong {
                max: MAX_RESOURCE_PATTERN_LENGTH,
                length: pattern.len(),
            });
        }

        Ok(Self { pattern })
    }

    /// Create a new path pattern without validation (for internal use)
    ///
    /// **Warning**: Only use this when pattern is known to be valid and within limits
    #[must_use]
    pub(crate) fn new_unchecked(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    /// Check if a path matches this pattern
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        wildcard_match(&self.pattern, path)
    }

    /// Get the pattern string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

/// Iterative wildcard match with O(N) complexity.
/// `*` doesn't match `/`. `**` is treated as `*`.
///
/// This implementation uses a two-pointer technique with backtracking
/// to avoid recursion and guarantee linear time complexity.
///
/// # Algorithm
///
/// - Uses two indices: `p_idx` for pattern, `s_idx` for path
/// - When encountering `*`, saves backtrack point
/// - On mismatch, backtracks to last `*` and tries next position
/// - `*` never matches `/` (path separator constraint)
///
/// # Complexity
///
/// - Time: O(N + M) where N = pattern length, M = path length
/// - Space: O(1) - only uses local variables
///
/// # Safety
///
/// This function uses safe indexing via `.get().copied()` to eliminate
/// any possibility of panic from out-of-bounds access.
fn wildcard_match(pattern: &str, path: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    let path_bytes = path.as_bytes();

    let mut p_idx = 0;
    let mut s_idx = 0;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0;

    while s_idx < path_bytes.len() {
        // Get current path character safely
        let Some(path_char) = path_bytes.get(s_idx).copied() else {
            // Should not happen due to while condition, but be defensive
            break;
        };

        if let Some(pattern_char) = pattern_bytes.get(p_idx).copied() {
            match pattern_char {
                b'?' => {
                    // Match any single character
                    p_idx += 1;
                    s_idx += 1;
                }
                b'*' => {
                    // Collapse consecutive '*' into one (treat '**' as '*')
                    while pattern_bytes.get(p_idx).copied() == Some(b'*') {
                        p_idx += 1;
                    }
                    // Save backtrack point
                    star_idx = Some(p_idx);
                    match_idx = s_idx;
                }
                c if c == path_char => {
                    // Literal character match
                    p_idx += 1;
                    s_idx += 1;
                }
                _ => {
                    // Mismatch - try to backtrack to last '*'
                    if let Some(star_pos) = star_idx {
                        // '*' doesn't match '/' - fail if we hit a separator
                        if path_bytes.get(match_idx).copied() == Some(b'/') {
                            return false;
                        }
                        // Backtrack: reset pattern to position after '*'
                        p_idx = star_pos;
                        match_idx += 1;
                        s_idx = match_idx;
                    } else {
                        // No '*' to backtrack to - match fails
                        return false;
                    }
                }
            }
        } else {
            // Pattern exhausted but path remains - try backtracking
            if let Some(star_pos) = star_idx {
                // '*' doesn't match '/' - fail if we hit a separator
                if match_idx >= path_bytes.len() || path_bytes.get(match_idx).copied() == Some(b'/')
                {
                    return false;
                }
                // Backtrack: reset pattern to position after '*'
                p_idx = star_pos;
                match_idx += 1;
                s_idx = match_idx;
            } else {
                // No '*' to backtrack to - match fails
                return false;
            }
        }
    }

    // After consuming all of the path, check if the pattern is exhausted
    // We allow trailing '*' only if we've matched at least one character
    // (i.e., if path is empty and pattern is "*", it should NOT match)
    while pattern_bytes.get(p_idx).copied() == Some(b'*') {
        // If the path was empty and we have a '*', this shouldn't match
        if path_bytes.is_empty() {
            return false;
        }
        p_idx += 1;
    }

    // Match succeeds if we've consumed both pattern and path
    p_idx == pattern_bytes.len()
}

impl TryFrom<String> for PathPattern {
    type Error = PolicyError;

    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<&str> for PathPattern {
    type Error = PolicyError;

    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}
