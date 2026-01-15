//! Fuzz target for YamlParser::parse
//!
//! This target tests YAML policy parsing with arbitrary strings to verify:
//! - serde_yaml handles malformed YAML without panicking
//! - Policy::validate() enforces T20 invariants even on parsed policies
//! - No memory exhaustion from deeply nested YAML
//!
//! T20 Invariants to verify:
//! - MAX_POLICY_NAME_LENGTH = 128
//! - MAX_RULES_PER_POLICY = 1024

#![no_main]

use libfuzzer_sys::fuzz_target;
use app_utils::yaml::{PolicyParser, YamlParser};
use core_policy::PolicyError;

fuzz_target!(|data: &str| {
    let parser = YamlParser;
    
    // Try to parse arbitrary YAML - should NEVER panic
    let result = parser.parse(data);
    
    match result {
        Ok(policy) => {
            // If parsing succeeded, verify T20 invariants hold
            
            // 1. Policy name length <= 128
            assert!(
                policy.name().len() <= 128,
                "Policy name exceeds MAX_POLICY_NAME_LENGTH"
            );
            
            // 2. Rules count <= 1024
            assert!(
                policy.rules().len() <= 1024,
                "Rules count exceeds MAX_RULES_PER_POLICY"
            );
            
            // 3. validate() should pass (was already called in parse)
            let validation = policy.validate();
            assert!(validation.is_ok(), "Parsed policy failed validation");
            
            // Verify we can access all fields without panic
            let _ = policy.version();
            let _ = policy.issued_at();
            let _ = policy.valid_until();
            let _ = policy.metadata();
        }
        Err(e) => {
            // Errors are expected - verify they're proper PolicyErrors
            match e {
                PolicyError::SerializationError(_) => {
                    // YAML parse error - expected for most random input
                }
                PolicyError::PolicyNameTooLong { length, max } => {
                    // T20 enforcement working
                    assert!(length > max);
                }
                PolicyError::TooManyRules { count, max } => {
                    // T20 enforcement working
                    assert!(count > max);
                }
                _ => {
                    // Other policy errors are acceptable
                }
            }
        }
    }
});

/// Additional structured tests for specific attack patterns
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_yaml() {
        let parser = YamlParser;
        let result = parser.parse("");
        // Empty string is not valid YAML for a Policy
        assert!(result.is_err());
    }

    #[test]
    fn test_deeply_nested_yaml() {
        let parser = YamlParser;
        
        // Create deeply nested YAML structure
        let depth = 100;
        let mut yaml = String::new();
        for i in 0..depth {
            yaml.push_str(&format!("{}level{}:\n", "  ".repeat(i), i));
        }
        yaml.push_str(&format!("{}value: test", "  ".repeat(depth)));
        
        // Should not panic
        let _ = parser.parse(&yaml);
    }

    #[test]
    fn test_huge_policy_name() {
        let parser = YamlParser;
        let huge_name = "a".repeat(200); // Exceeds MAX_POLICY_NAME_LENGTH
        
        let yaml = format!(r#"
name: "{}"
version: "1.0.0"
issued_at: "2024-01-01T00:00:00Z"
rules: []
"#, huge_name);
        
        let result = parser.parse(&yaml);
        // Should fail with PolicyNameTooLong
        assert!(result.is_err());
    }

    #[test]
    fn test_many_rules() {
        let parser = YamlParser;
        
        // Create policy with > 1024 rules
        let mut rules = String::new();
        for i in 0..1100 {
            rules.push_str(&format!("  - name: rule{}\n", i));
            rules.push_str("    actions: [\"read\"]\n");
            rules.push_str("    resource: \"*\"\n");
            rules.push_str("    effect: allow\n");
        }
        
        let yaml = format!(r#"
name: "test"
version: "1.0.0"
issued_at: "2024-01-01T00:00:00Z"
rules:
{}
"#, rules);
        
        let result = parser.parse(&yaml);
        // Should fail with TooManyRules
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_yaml() {
        let parser = YamlParser;
        
        let malformed_cases = [
            "{{{",
            "key: [value",
            "- - - - -",
            "key\n  : value",
            "\x00\x01\x02",
        ];
        
        for case in malformed_cases {
            // Should not panic
            let _ = parser.parse(case);
        }
    }

    #[test]
    fn test_valid_minimal_policy() {
        let parser = YamlParser;
        
        let yaml = r#"
name: "test"
version: "1.0.0"
issued_at: "2024-01-01T00:00:00Z"
rules: []
"#;
        
        let result = parser.parse(yaml);
        assert!(result.is_ok());
    }
}
