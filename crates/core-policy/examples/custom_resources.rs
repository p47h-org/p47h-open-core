//! # Custom Resources Example
//!
//! Demonstrates how to extend the policy engine with custom resource matchers
//! by implementing the `ResourceMatcher` trait and registering them in the registry.
//!
//! ## Run
//!
//! ```bash
//! cargo run -p core-policy --example custom_resources
//! ```

use core_policy::{Resource, ResourceMatcher, ResourceMatcherRegistry};
use std::collections::HashMap;

// ============================================================================
// MATCHER CUSTOM #1: S3 Buckets with Wildcards
// ============================================================================

/// Matcher for S3 buckets with AWS wildcard support
///
/// Supports patterns like:
/// - `my-bucket/*` - All objects in the bucket
/// - `my-bucket/data/*.csv` - CSV files in subfolder
/// - `arn:aws:s3:::bucket-name/*` - Full ARN
struct S3BucketMatcher;

impl S3BucketMatcher {
    fn matches_pattern(pattern: &str, path: &str) -> bool {
        // Simplified: supports * as wildcard
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                let prefix = parts[0];
                let suffix = parts[1];
                return path.starts_with(prefix) && path.ends_with(suffix);
            }
        }

        pattern == path
    }
}

impl ResourceMatcher for S3BucketMatcher {
    fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
        match (pattern, target) {
            (
                Resource::Custom {
                    resource_type: t1,
                    path: p,
                },
                Resource::Custom {
                    resource_type: t2,
                    path: t,
                },
            ) if t1 == "s3" && t2 == "s3" => Self::matches_pattern(p, t),
            _ => false,
        }
    }

    fn name(&self) -> &str {
        "S3BucketMatcher"
    }

    fn priority(&self) -> u32 {
        10 // High priority
    }
}

// ============================================================================
// MATCHER CUSTOM #2: Docker Containers with Tags
// ============================================================================

/// Matcher for Docker containers with tag support
///
/// Supports patterns like:
/// - `nginx:*` - Any nginx version
/// - `myapp:1.*` - Version 1.x
/// - `registry.example.com/myapp:latest` - Private registry
struct DockerImageMatcher;

impl DockerImageMatcher {
    fn matches_image(pattern: &str, image: &str) -> bool {
        // Separate image:tag
        let pattern_parts: Vec<&str> = pattern.split(':').collect();
        let image_parts: Vec<&str> = image.split(':').collect();

        if pattern_parts.len() != 2 || image_parts.len() != 2 {
            return pattern == image;
        }

        let (p_image, p_tag) = (pattern_parts[0], pattern_parts[1]);
        let (i_image, i_tag) = (image_parts[0], image_parts[1]);

        // Match image
        if p_image != "*" && p_image != i_image {
            return false;
        }

        // Match tag with wildcards
        if p_tag == "*" {
            return true;
        }

        if let Some(prefix) = p_tag.strip_suffix('*') {
            return i_tag.starts_with(prefix);
        }

        p_tag == i_tag
    }
}

impl ResourceMatcher for DockerImageMatcher {
    fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
        match (pattern, target) {
            (
                Resource::Custom {
                    resource_type: t1,
                    path: p,
                },
                Resource::Custom {
                    resource_type: t2,
                    path: t,
                },
            ) if t1 == "docker" && t2 == "docker" => Self::matches_image(p, t),
            _ => false,
        }
    }

    fn name(&self) -> &str {
        "DockerImageMatcher"
    }
}

// ============================================================================
// MATCHER CUSTOM #3: Database con Permisos Granulares
// ============================================================================

/// Matcher for databases with granular table/column permissions
///
/// Supports patterns like:
/// - `postgres://db/table` - Full table
/// - `postgres://db/table/column` - Specific column
/// - `postgres://db/*` - All tables
struct DatabaseMatcher {
    // Cache of compiled patterns (in production we would use regex)
    #[allow(dead_code)] // Reserved for future pattern caching
    cache: HashMap<String, String>,
}

impl DatabaseMatcher {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    fn matches_database_path(pattern: &str, path: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('/').collect();
        let path_parts: Vec<&str> = path.split('/').collect();

        if pattern_parts.len() != path_parts.len() {
            // Allow final wildcard
            if let Some(prefix) = pattern.strip_suffix("/*") {
                return path.starts_with(prefix);
            }
            return false;
        }

        // Match part by part
        for (p, t) in pattern_parts.iter().zip(path_parts.iter()) {
            if *p != "*" && p != t {
                return false;
            }
        }

        true
    }
}

impl ResourceMatcher for DatabaseMatcher {
    fn matches(&self, pattern: &Resource, target: &Resource) -> bool {
        match (pattern, target) {
            (
                Resource::Custom {
                    resource_type: t1,
                    path: p,
                },
                Resource::Custom {
                    resource_type: t2,
                    path: t,
                },
            ) if t1 == "database" && t2 == "database" => Self::matches_database_path(p, t),
            _ => false,
        }
    }

    fn name(&self) -> &str {
        "DatabaseMatcher"
    }

    fn priority(&self) -> u32 {
        5
    }
}

// ============================================================================
// MAIN: Extensibility Demonstration
// ============================================================================

fn main() {
    println!("=== Custom Resources Example ===\n");

    // 1. Create registry
    println!("1. Creating ResourceMatcherRegistry...");
    let mut registry = ResourceMatcherRegistry::new();
    println!("   Registry created (0 matchers)\n");

    // 2. Register custom matchers (without modifying core code)
    println!("2. Registering custom matchers...");

    registry.register("s3", Box::new(S3BucketMatcher));
    println!("   S3BucketMatcher registered");

    registry.register("docker", Box::new(DockerImageMatcher));
    println!("   DockerImageMatcher registered");

    registry.register("database", Box::new(DatabaseMatcher::new()));
    println!("   DatabaseMatcher registered\n");

    // 3. List matchers
    println!("3. Available matchers:");
    for matcher_type in registry.list_matchers() {
        println!("   - {}", matcher_type);
    }
    println!();

    // ========================================================================
    // TEST S3 Bucket Matcher
    // ========================================================================

    println!("4. Testing S3BucketMatcher...");

    let s3_pattern = Resource::Custom {
        resource_type: "s3".to_string(),
        path: "my-bucket/data/*.csv".to_string(),
    };

    let s3_match = Resource::Custom {
        resource_type: "s3".to_string(),
        path: "my-bucket/data/sales.csv".to_string(),
    };

    let s3_no_match = Resource::Custom {
        resource_type: "s3".to_string(),
        path: "my-bucket/logs/error.log".to_string(),
    };

    assert!(registry.matches(&s3_pattern, &s3_match));
    println!("   'my-bucket/data/*.csv' matches 'my-bucket/data/sales.csv'");

    assert!(!registry.matches(&s3_pattern, &s3_no_match));
    println!("   'my-bucket/data/*.csv' NOT matches 'my-bucket/logs/error.log'\n");

    // ========================================================================
    // TEST Docker Image Matcher
    // ========================================================================

    println!("5. Testing DockerImageMatcher...");

    let docker_pattern = Resource::Custom {
        resource_type: "docker".to_string(),
        path: "nginx:1.*".to_string(),
    };

    let docker_match = Resource::Custom {
        resource_type: "docker".to_string(),
        path: "nginx:1.21".to_string(),
    };

    let docker_no_match = Resource::Custom {
        resource_type: "docker".to_string(),
        path: "nginx:2.0".to_string(),
    };

    assert!(registry.matches(&docker_pattern, &docker_match));
    println!("   'nginx:1.*' matches 'nginx:1.21'");

    assert!(!registry.matches(&docker_pattern, &docker_no_match));
    println!("   'nginx:1.*' NOT matches 'nginx:2.0'\n");

    // ========================================================================
    // TEST Database Matcher
    // ========================================================================

    println!("6. Testing DatabaseMatcher...");

    let db_pattern = Resource::Custom {
        resource_type: "database".to_string(),
        path: "postgres://mydb/*".to_string(),
    };

    let db_match = Resource::Custom {
        resource_type: "database".to_string(),
        path: "postgres://mydb/users".to_string(),
    };

    assert!(registry.matches(&db_pattern, &db_match));
    println!("   'postgres://mydb/*' matches 'postgres://mydb/users'\n");

    // ========================================================================
    // TEST Backward Compatibility (built-in resources)
    // ========================================================================

    println!("7. Verifying backward compatibility...");

    let file_pattern = Resource::File("/data/*.txt".to_string());
    let file_target = Resource::File("/data/file.txt".to_string());

    assert!(registry.matches(&file_pattern, &file_target));
    println!("   Resource::File still works without custom matcher");

    let usb_pattern = Resource::Usb("usb-*".to_string());
    let usb_target = Resource::Usb("usb-keyboard".to_string());

    assert!(registry.matches(&usb_pattern, &usb_target));
    println!("   Resource::Usb still works without custom matcher");

    let all_pattern = Resource::All;
    let any_target = Resource::File("/anything".to_string());

    assert!(registry.matches(&all_pattern, &any_target));
    println!("   Resource::All still works without custom matcher\n");

    // ========================================================================
    // STATS
    // ========================================================================

    println!("8. Verifying registry...");
    assert_eq!(registry.count(), 3);
    println!("   {} matchers registered", registry.count());

    assert!(registry.has_matcher("s3"));
    assert!(registry.has_matcher("docker"));
    assert!(registry.has_matcher("database"));
    println!("   All matchers present\n");

    println!("=== DEMO COMPLETED ===");
    println!("\nResult: Added 3 custom resource types using the matcher registry.");
}
