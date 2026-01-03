//! # Resource Matcher
//!
//! Extensible resource matching system that allows custom matchers to be registered
//! for handling domain-specific resource types without modifying core types.
//!
//! ## Usage Example
//!
//! ```rust
//! use core_policy::resource_matcher::{ResourceMatcher, ResourceMatcherRegistry};
//! use core_policy::Resource;
//!
//! // 1. Implement custom matcher
//! struct S3BucketMatcher;
//!
//! impl ResourceMatcher for S3BucketMatcher {
//!     fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
//!         // Custom logic for S3
//!         match (pattern, target) {
//!             (Resource::Custom { resource_type: rt1, path: p },
//!              Resource::Custom { resource_type: rt2, path: t })
//!              if rt1 == "s3" && rt2 == "s3" => {
//!                  // Simple example: exact match or wildcard
//!                  p == t || p == "*"
//!             }
//!             _ => false,
//!         }
//!     }
//! }
//!
//! // 2. Register matcher
//! let mut registry = ResourceMatcherRegistry::new();
//! registry.register("s3", Box::new(S3BucketMatcher));
//!
//! // 3. Use matcher
//! let pattern = Resource::Custom {
//!     resource_type: "s3".into(),
//!     path: "*".into(),
//! };
//! let target = Resource::Custom {
//!     resource_type: "s3".into(),
//!     path: "bucket-1".into(),
//! };
//!
//! assert!(registry.matches(&pattern, &target));
//! ```

use crate::Resource;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Trait for implementing custom resource matching logic
pub trait ResourceMatcher: Send + Sync {
    /// Returns true if the pattern matches the target
    fn matches(&self, pattern: &Resource, target: &Resource) -> bool;

    /// Returns the priority of this matcher (higher means checked first)
    fn priority(&self) -> u32 {
        0
    }

    /// Returns the name of the matcher strategy
    fn name(&self) -> &str {
        "ResourceMatcher"
    }
}

/// Registry for custom resource matchers
pub struct ResourceMatcherRegistry {
    matchers: BTreeMap<String, Box<dyn ResourceMatcher>>,
}

impl ResourceMatcherRegistry {
    /// Creates a new empty registry
    pub fn new() -> Self {
        Self {
            matchers: BTreeMap::new(),
        }
    }

    /// Registers a new matcher for a resource type
    ///
    /// `Some(old_matcher)` if there was a previous matcher, `None` if new
    ///
    pub fn register(
        &mut self,
        resource_type: impl Into<String>,
        matcher: Box<dyn ResourceMatcher>,
    ) -> Option<Box<dyn ResourceMatcher>> {
        self.matchers.insert(resource_type.into(), matcher)
    }

    /// Unregisters a matcher
    ///
    /// # Returns
    ///
    /// `Some(matcher)` if it existed, `None` if it was not registered
    pub fn unregister(&mut self, resource_type: &str) -> Option<Box<dyn ResourceMatcher>> {
        self.matchers.remove(resource_type)
    }

    /// Checks if there is a matcher registered for a type
    pub fn has_matcher(&self, resource_type: &str) -> bool {
        self.matchers.contains_key(resource_type)
    }

    /// Executes matching using the appropriate matcher
    ///
    /// If there is no custom matcher, it uses the default `Resource::matches()` method.
    ///
    pub fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
        // Try custom matcher first
        if let Resource::Custom { resource_type, .. } = pattern {
            if let Some(matcher) = self.matchers.get(resource_type) {
                return matcher.matches(pattern, target);
            }
        }

        // Fallback to default matching
        pattern.matches(target)
    }

    /// Lists all registered resource types
    pub fn list_matchers(&self) -> Vec<String> {
        self.matchers.keys().cloned().collect()
    }

    /// Counts the number of registered matchers
    pub fn count(&self) -> usize {
        self.matchers.len()
    }

    /// Clears all matchers
    pub fn clear(&mut self) {
        self.matchers.clear();
    }
}

impl Default for ResourceMatcherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    // Test matcher: always returns true
    struct AlwaysMatcher;
    impl ResourceMatcher for AlwaysMatcher {
        fn matches(&self, _pattern: &Resource, _target: &Resource) -> bool {
            true
        }
    }

    // Test matcher: always returns false
    struct NeverMatcher;
    impl ResourceMatcher for NeverMatcher {
        fn matches(&self, _pattern: &Resource, _target: &Resource) -> bool {
            false
        }
    }

    // Test matcher: exact path matching
    struct ExactMatcher;
    impl ResourceMatcher for ExactMatcher {
        fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
            match (pattern, target) {
                (
                    Resource::Custom {
                        resource_type: t1,
                        path: p1,
                    },
                    Resource::Custom {
                        resource_type: t2,
                        path: p2,
                    },
                ) => t1 == t2 && p1 == p2,
                _ => false,
            }
        }
    }

    // Test matcher with custom priority
    struct PriorityMatcher;
    impl ResourceMatcher for PriorityMatcher {
        fn matches(&self, _: &Resource, _: &Resource) -> bool {
            true
        }

        fn priority(&self) -> u32 {
            100
        }
    }

    #[test]
    fn test_registry_new() {
        let registry = ResourceMatcherRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_register_matcher() {
        let mut registry = ResourceMatcherRegistry::new();

        registry.register("test", Box::new(AlwaysMatcher));
        assert_eq!(registry.count(), 1);
        assert!(registry.has_matcher("test"));
    }

    #[test]
    fn test_register_duplicate_replaces() {
        let mut registry = ResourceMatcherRegistry::new();

        let old = registry.register("test", Box::new(AlwaysMatcher));
        assert!(old.is_none());

        let old = registry.register("test", Box::new(NeverMatcher));
        assert!(old.is_some());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_unregister_matcher() {
        let mut registry = ResourceMatcherRegistry::new();

        registry.register("test", Box::new(AlwaysMatcher));
        assert_eq!(registry.count(), 1);

        let removed = registry.unregister("test");
        assert!(removed.is_some());
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_unregister_nonexistent() {
        let mut registry = ResourceMatcherRegistry::new();

        let removed = registry.unregister("nonexistent");
        assert!(removed.is_none());
    }

    #[test]
    fn test_has_matcher() {
        let mut registry = ResourceMatcherRegistry::new();

        assert!(!registry.has_matcher("test"));

        registry.register("test", Box::new(AlwaysMatcher));
        assert!(registry.has_matcher("test"));

        registry.unregister("test");
        assert!(!registry.has_matcher("test"));
    }

    #[test]
    fn test_matches_with_custom_matcher() {
        let mut registry = ResourceMatcherRegistry::new();
        registry.register("test", Box::new(AlwaysMatcher));

        let pattern = Resource::Custom {
            resource_type: "test".into(),
            path: "anything".into(),
        };
        let target = Resource::Custom {
            resource_type: "test".into(),
            path: "different".into(),
        };

        assert!(registry.matches(&pattern, &target));
    }

    #[test]
    fn test_matches_without_custom_matcher_uses_default() {
        let registry = ResourceMatcherRegistry::new();

        let pattern = Resource::File("/home/*".into());
        let target = Resource::File("/home/user".into());

        // Without custom matcher, it should use the default Resource::matches() method
        assert!(registry.matches(&pattern, &target));
    }

    #[test]
    fn test_exact_matcher() {
        let mut registry = ResourceMatcherRegistry::new();
        registry.register("exact", Box::new(ExactMatcher));

        let pattern = Resource::Custom {
            resource_type: "exact".into(),
            path: "/path/to/file".into(),
        };
        let target_match = Resource::Custom {
            resource_type: "exact".into(),
            path: "/path/to/file".into(),
        };
        let target_no_match = Resource::Custom {
            resource_type: "exact".into(),
            path: "/different/path".into(),
        };

        assert!(registry.matches(&pattern, &target_match));
        assert!(!registry.matches(&pattern, &target_no_match));
    }

    #[test]
    fn test_list_matchers() {
        let mut registry = ResourceMatcherRegistry::new();

        registry.register("s3", Box::new(AlwaysMatcher));
        registry.register("docker", Box::new(NeverMatcher));

        let list = registry.list_matchers();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&"s3".to_string()));
        assert!(list.contains(&"docker".to_string()));
    }

    #[test]
    fn test_count() {
        let mut registry = ResourceMatcherRegistry::new();
        assert_eq!(registry.count(), 0);

        registry.register("a", Box::new(AlwaysMatcher));
        assert_eq!(registry.count(), 1);

        registry.register("b", Box::new(NeverMatcher));
        assert_eq!(registry.count(), 2);

        registry.unregister("a");
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_clear() {
        let mut registry = ResourceMatcherRegistry::new();

        registry.register("a", Box::new(AlwaysMatcher));
        registry.register("b", Box::new(NeverMatcher));
        assert_eq!(registry.count(), 2);

        registry.clear();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_matcher_priority() {
        let matcher = PriorityMatcher;
        assert_eq!(matcher.priority(), 100);
    }

    #[test]
    fn test_fallback_to_default_file_matching() {
        let registry = ResourceMatcherRegistry::new();

        // Test File matching (without custom matcher)
        let pattern = Resource::File("/data/*.txt".into());
        let target = Resource::File("/data/file.txt".into());
        assert!(registry.matches(&pattern, &target));
    }

    #[test]
    fn test_fallback_to_default_usb_matching() {
        let registry = ResourceMatcherRegistry::new();

        // Test USB matching (without custom matcher)
        let pattern = Resource::Usb("usb-*".into());
        let target = Resource::Usb("usb-keyboard".into());
        assert!(registry.matches(&pattern, &target));
    }

    #[test]
    fn test_fallback_to_default_all_matching() {
        let registry = ResourceMatcherRegistry::new();

        // Test All wildcard (without custom matcher)
        let pattern = Resource::All;
        let target = Resource::File("/anything".into());
        assert!(registry.matches(&pattern, &target));
    }
}
