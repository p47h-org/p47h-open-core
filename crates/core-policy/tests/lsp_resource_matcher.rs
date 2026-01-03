//! # LSP Tests for ResourceMatcher
//!
//! Verifies that all `ResourceMatcher` implementations fulfill
//! the trait contracts, especially the **reflexivity** property.
//!
//! ## LSP Contracts for ResourceMatcher
//!
//! 1. **Reflexivity**: `matches(x, x)` always returns `true`
//! 2. **Determinism**: Same input -> same output
//! 3. **Thread-safety**: Implementations must be Send + Sync
//!
//! ## Architecture
//!
//! ```text
//! ResourceMatcher (base trait)
//!   ├── ExactMatcher (strict equality)
//!   └── WildcardMatcher (uses Resource::matches built-in)
//! ```

use core_policy::{Resource, ResourceMatcher};

// ============================================================================
// Test Matcher Implementations
// ============================================================================

/// Exact matcher - only accepts perfect equality
#[derive(Debug)]
struct ExactMatcher;

impl ResourceMatcher for ExactMatcher {
    fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
        pattern == target
    }

    fn name(&self) -> &str {
        "ExactMatcher"
    }
}

/// Wildcard matcher - uses the built-in Resource::matches logic
#[derive(Debug)]
struct WildcardMatcher;

impl ResourceMatcher for WildcardMatcher {
    fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
        pattern.matches(target)
    }

    fn name(&self) -> &str {
        "WildcardMatcher"
    }

    fn priority(&self) -> u32 {
        100
    }
}

// ============================================================================
// LSP Property Tests - Generic over ResourceMatcher
// ============================================================================

/// LSP Property 1: Reflexivity
///
/// Contract: `matches(x, x)` MUST return `true` for any resource x
fn test_reflexivity<M: ResourceMatcher>(matcher: &M, resource: &Resource) {
    assert!(
        matcher.matches(resource, resource),
        "{resource:?} does not match itself for matcher {}",
        matcher.name()
    );
}

/// LSP Property 2: Wildcards are extensions
fn test_determinism<M: ResourceMatcher>(matcher: &M, pattern: &Resource, target: &Resource) {
    let result1 = matcher.matches(pattern, target);
    let result2 = matcher.matches(pattern, target);

    assert_eq!(
        result1,
        result2,
        "Determinism violated: matcher {} returned different results for same input",
        matcher.name()
    );
}

/// LSP Property 3: Thread-safety (compile-time check)
fn assert_send_sync<M: ResourceMatcher>() {
    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}

    is_send::<M>();
    is_sync::<M>();
}

// ============================================================================
// Concrete Tests - ExactMatcher
// ============================================================================

#[test]
fn test_exact_matcher_reflexivity() {
    let matcher = ExactMatcher;

    // Test all Resource variants
    let resources = vec![
        Resource::All,
        Resource::File("/test/file.txt".into()),
        Resource::Usb("device01".into()),
        Resource::Tunnel("vpn-main".into()),
        Resource::Custom {
            resource_type: "database".into(),
            path: "/db/users".into(),
        },
    ];

    for resource in resources {
        test_reflexivity(&matcher, &resource);
    }
}

#[test]
fn test_exact_matcher_determinism() {
    let matcher = ExactMatcher;

    let pattern = Resource::File("/pattern.txt".into());
    let target = Resource::File("/target.txt".into());

    test_determinism(&matcher, &pattern, &target);
}

#[test]
fn test_exact_matcher_equality() {
    let matcher = ExactMatcher;

    // Same resources should match
    let file1 = Resource::File("/test.txt".into());
    let file2 = Resource::File("/test.txt".into());
    assert!(matcher.matches(&file1, &file2));

    // Different resources should not match
    let file3 = Resource::File("/other.txt".into());
    assert!(!matcher.matches(&file1, &file3));

    // Different types should not match
    let usb = Resource::Usb("/test.txt".into());
    assert!(!matcher.matches(&file1, &usb));
}

// ============================================================================
// Concrete Tests - WildcardMatcher
// ============================================================================

#[test]
fn test_wildcard_matcher_reflexivity() {
    let matcher = WildcardMatcher;

    let resources = vec![
        Resource::All,
        Resource::File("/wildcard.txt".into()),
        Resource::File("/path/*.txt".into()),
        Resource::Usb("device*".into()),
        Resource::Tunnel("tunnel-*".into()),
        Resource::Custom {
            resource_type: "db".into(),
            path: "/data/*".into(),
        },
    ];

    for resource in resources {
        test_reflexivity(&matcher, &resource);
    }
}

#[test]
fn test_wildcard_matcher_determinism() {
    let matcher = WildcardMatcher;

    let pattern = Resource::All;
    let target = Resource::File("/any.txt".into());

    test_determinism(&matcher, &pattern, &target);
}

#[test]
fn test_wildcard_matcher_all_pattern() {
    let matcher = WildcardMatcher;

    let pattern = Resource::All;

    // All should match everything
    let targets = vec![
        Resource::All,
        Resource::File("/file.txt".into()),
        Resource::Usb("device01".into()),
        Resource::Tunnel("tunnel-main".into()),
        Resource::Custom {
            resource_type: "anything".into(),
            path: "/path".into(),
        },
    ];

    for target in targets {
        assert!(
            matcher.matches(&pattern, &target),
            "Resource::All pattern should match {:?}",
            target
        );
    }
}

#[test]
fn test_wildcard_matcher_file_wildcard() {
    let matcher = WildcardMatcher;

    // Pattern with wildcard
    let pattern = Resource::File("/home/*".into());

    // Should match files directly under /home/
    assert!(matcher.matches(&pattern, &Resource::File("/home/file.txt".into())));

    // Should not match files outside /home/
    assert!(!matcher.matches(&pattern, &Resource::File("/tmp/file.txt".into())));

    // Test nested path matching
    let nested_pattern = Resource::File("/data/**".into());
    assert!(matcher.matches(&nested_pattern, &Resource::File("/data/file.txt".into())));
}

#[test]
fn test_wildcard_matcher_exact_match() {
    let matcher = WildcardMatcher;

    // Without wildcard, should only match exact path
    let pattern = Resource::File("/exact/path.txt".into());

    assert!(matcher.matches(&pattern, &Resource::File("/exact/path.txt".into())));
    assert!(!matcher.matches(&pattern, &Resource::File("/exact/path2.txt".into())));
}

// ============================================================================
// Thread-Safety Verification
// ============================================================================

#[test]
fn test_all_matchers_are_send_sync() {
    assert_send_sync::<ExactMatcher>();
    assert_send_sync::<WildcardMatcher>();
}

// ============================================================================
// LSP Substitution Tests
// ============================================================================

/// Test that different matchers can be used interchangeably
#[test]
fn test_matcher_substitution() {
    // Generic function that uses any ResourceMatcher
    fn apply_matcher<M: ResourceMatcher>(
        matcher: &M,
        pattern: &Resource,
        targets: &[Resource],
    ) -> Vec<bool> {
        targets
            .iter()
            .map(|target| matcher.matches(pattern, target))
            .collect()
    }

    let pattern = Resource::File("/test.txt".into());
    let targets = vec![
        Resource::File("/test.txt".into()),
        Resource::File("/other.txt".into()),
        Resource::All,
    ];

    // All matchers should work with same interface
    let exact_results = apply_matcher(&ExactMatcher, &pattern, &targets);
    let wildcard_results = apply_matcher(&WildcardMatcher, &pattern, &targets);

    // Results may differ (different strategies), but all should work
    assert_eq!(exact_results.len(), 3);
    assert_eq!(wildcard_results.len(), 3);

    // But reflexivity must hold for all
    assert!(exact_results[0], "ExactMatcher must satisfy reflexivity");
    assert!(
        wildcard_results[0],
        "WildcardMatcher must satisfy reflexivity"
    );
}

/// Test that matchers can be stored as trait objects
#[test]
fn test_matcher_trait_objects() {
    let matchers: Vec<Box<dyn ResourceMatcher>> =
        vec![Box::new(ExactMatcher), Box::new(WildcardMatcher)];

    let resource = Resource::File("/test.txt".into());

    // All matchers should satisfy reflexivity
    for matcher in matchers {
        assert!(
            matcher.matches(&resource, &resource),
            "Matcher {} violates reflexivity",
            matcher.name()
        );
    }
}

// ============================================================================
// Property-Based Testing with Multiple Resources
// ============================================================================

#[test]
fn test_reflexivity_property_all_variants() {
    let matchers: Vec<Box<dyn ResourceMatcher>> =
        vec![Box::new(ExactMatcher), Box::new(WildcardMatcher)];

    let resources = vec![
        Resource::All,
        Resource::File("/a".into()),
        Resource::File("/a/b/c/d/e/f".into()),
        Resource::File("/".into()),
        Resource::Usb("device-01".into()),
        Resource::Usb("device-*".into()),
        Resource::Tunnel("vpn-main".into()),
        Resource::Tunnel("tunnel-*".into()),
        Resource::Custom {
            resource_type: "custom-1".into(),
            path: "/path".into(),
        },
        Resource::Custom {
            resource_type: "".into(),
            path: "".into(),
        },
    ];

    // Test reflexivity for all matcher × resource combinations
    for matcher in &matchers {
        for resource in &resources {
            assert!(
                matcher.matches(resource, resource),
                "Reflexivity violated for {:?} with matcher {}",
                resource,
                matcher.name()
            );
        }
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_paths() {
    let matchers: Vec<Box<dyn ResourceMatcher>> =
        vec![Box::new(ExactMatcher), Box::new(WildcardMatcher)];

    let empty_file = Resource::File("".into());
    let empty_usb = Resource::Usb("".into());

    // Reflexivity must hold even for empty paths
    for matcher in &matchers {
        assert!(matcher.matches(&empty_file, &empty_file));
        assert!(matcher.matches(&empty_usb, &empty_usb));
    }
}

#[test]
fn test_special_characters_in_paths() {
    let matchers: Vec<Box<dyn ResourceMatcher>> =
        vec![Box::new(ExactMatcher), Box::new(WildcardMatcher)];

    let special_resources = vec![
        Resource::File("/path with spaces/file.txt".into()),
        Resource::File("/path/with/unicode/文件.txt".into()),
        Resource::File("/path/with/emoji/📁/file.txt".into()),
        Resource::File("/path/../normalized".into()),
        Resource::File("//double//slashes//".into()),
    ];

    // Reflexivity must hold for special characters
    for matcher in &matchers {
        for resource in &special_resources {
            assert!(matcher.matches(resource, resource));
        }
    }
}

// ============================================================================
// Documentation Test
// ============================================================================

/// Documents the LSP compliance of ResourceMatcher implementations
///
/// ## LSP Analysis
///
/// Both matchers (ExactMatcher, WildcardMatcher) are FULLY LSP-compliant:
///
/// 1. **Reflexivity preserved**: All satisfy `matches(x, x) == true`
/// 2. **Determinism preserved**: Same input -> same output
/// 3. **Thread-safety**: All are Send + Sync
/// 4. **Substitutability**: Can be used interchangeably through trait
///
/// ### Difference from Verifier
///
/// Unlike Verifier (where ContextualVerifier is stricter), all ResourceMatcher
/// implementations can safely substitute each other because:
///
/// - They implement the SAME matching semantics (reflexivity)
/// - They differ only in EXTENSION (wildcard support), not restriction
/// - Core contract is preserved: a resource always matches itself
///
/// ## Conclusion
///
/// ResourceMatcher is a BETTER example of LSP compliance than Verifier.
#[test]
fn test_lsp_compliance_documentation() {
    // This test exists to document LSP properties
    // Actual validation is done in other tests
}
