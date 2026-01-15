//! Fuzz target for parse_resource
//!
//! This target tests the resource parsing function with arbitrary strings
//! to find potential panics or crashes in string manipulation.
//!
//! Attack vectors tested:
//! - Very long strings (memory exhaustion)
//! - Many colons (split_once edge cases)
//! - Empty strings
//! - Unicode edge cases

#![no_main]

use libfuzzer_sys::fuzz_target;
use p47h_engine::parse_resource;
use core_policy::Resource;

fuzz_target!(|data: &str| {
    // parse_resource should NEVER panic on any string input
    let result = parse_resource(data);
    
    // Verify the result is a valid Resource variant
    match result {
        Resource::All => {
            // Only "*" should produce All
            assert_eq!(data, "*");
        }
        Resource::File(path) => {
            // If prefix was "file:", path should be the remainder
            if let Some(stripped) = data.strip_prefix("file:") {
                assert_eq!(path, stripped);
            } else if !data.contains(':') {
                // Unqualified paths default to File
                assert_eq!(path, data);
            }
        }
        Resource::Usb(id) => {
            // Should have "usb:" prefix
            if let Some(stripped) = data.strip_prefix("usb:") {
                assert_eq!(id, stripped);
            }
        }
        Resource::Tunnel(id) => {
            // Should have "tunnel:" prefix
            if let Some(stripped) = data.strip_prefix("tunnel:") {
                assert_eq!(id, stripped);
            }
        }
        Resource::Custom { resource_type, path } => {
            // Should have "type:path" format
            if let Some((t, p)) = data.split_once(':') {
                // Verify it wasn't one of the known prefixes
                assert!(t != "file" && t != "usb" && t != "tunnel");
                assert_eq!(resource_type, t);
                assert_eq!(path, p);
            }
        }
    }
});

/// Additional structured tests for edge cases
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        let result = parse_resource("");
        // Empty string defaults to File("")
        assert!(matches!(result, Resource::File(_)));
    }

    #[test]
    fn test_only_colon() {
        let result = parse_resource(":");
        // ":" splits to ("", "")
        assert!(matches!(result, Resource::Custom { .. }));
    }

    #[test]
    fn test_many_colons() {
        let result = parse_resource("a:b:c:d:e:f");
        // split_once takes only the first colon
        if let Resource::Custom { resource_type, path } = result {
            assert_eq!(resource_type, "a");
            assert_eq!(path, "b:c:d:e:f");
        } else {
            panic!("Expected Custom resource");
        }
    }

    #[test]
    fn test_unicode() {
        // Unicode in resource paths
        let result = parse_resource("file:документы/файл.txt");
        assert!(matches!(result, Resource::File(_)));
        
        let result = parse_resource("カスタム:パス");
        assert!(matches!(result, Resource::Custom { .. }));
    }

    #[test]
    fn test_very_long_string() {
        // Very long string (1MB)
        let long_input = "a".repeat(1_000_000);
        let result = parse_resource(&long_input);
        // Should not panic, returns File variant
        assert!(matches!(result, Resource::File(_)));
    }

    #[test]
    fn test_null_bytes() {
        // String with null bytes (embedded zeros)
        let with_nulls = "file:\x00path\x00name";
        let result = parse_resource(with_nulls);
        assert!(matches!(result, Resource::File(_)));
    }
}
