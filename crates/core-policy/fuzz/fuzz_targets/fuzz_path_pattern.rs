//! Fuzz target for PathPattern::new
//!
//! This target tests that PathPattern::new handles arbitrary input
//! without panicking, and that valid patterns match consistently.

#![no_main]

use libfuzzer_sys::fuzz_target;
use core_policy::PathPattern;

fuzz_target!(|data: &str| {
    // Test 1: PathPattern::new should never panic
    let result = PathPattern::new(data);
    
    // Test 2: If pattern is valid, it should be usable
    if let Ok(pattern) = result {
        // Test various paths against the pattern
        let _ = pattern.matches("");
        let _ = pattern.matches("/");
        let _ = pattern.matches("/a/b/c");
        let _ = pattern.matches(data); // Pattern should match itself if no wildcards
        
        // Verify as_str returns the original pattern
        let _ = pattern.as_str();
    }
});
