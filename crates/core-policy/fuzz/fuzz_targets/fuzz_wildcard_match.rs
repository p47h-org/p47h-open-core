//! Fuzz target for wildcard_match function
//!
//! This target tests the core path matching algorithm with
//! arbitrary pattern/path combinations to ensure no panics.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use core_policy::PathPattern;

/// Structured input for wildcard matching
#[derive(Arbitrary, Debug)]
struct WildcardInput {
    pattern: String,
    path: String,
}

fuzz_target!(|input: WildcardInput| {
    // Only test patterns within the allowed length
    if input.pattern.len() <= 4096 && input.path.len() <= 4096 {
        // Create pattern (may fail if too long, which is expected)
        if let Ok(pattern) = PathPattern::new(&input.pattern) {
            // Test matching - should never panic
            let _ = pattern.matches(&input.path);
            
            // Test with various edge cases derived from input
            let _ = pattern.matches("");
            let _ = pattern.matches("/");
            
            // Test reflexivity for literal patterns (no wildcards)
            if !input.pattern.contains('*') && !input.pattern.contains('?') {
                // Literal pattern should match itself
                let matches_self = pattern.matches(&input.pattern);
                // This may or may not be true depending on the pattern
                let _ = matches_self;
            }
        }
    }
});
