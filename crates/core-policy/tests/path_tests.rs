//! Path pattern matching tests
//!
//! Comprehensive test suite for wildcard matching implementation,
//! including stress tests for deep paths and edge cases.

use core_policy::{PathPattern, PolicyError, MAX_RESOURCE_PATTERN_LENGTH};

#[test]
fn test_basic_exact_match() {
    let p = PathPattern::new("/home/user/file.txt").unwrap();
    assert!(p.matches("/home/user/file.txt"));
    assert!(!p.matches("/home/user/other.txt"));
}

#[test]
fn test_single_wildcard() {
    let p = PathPattern::new("/home/*/file.txt").unwrap();
    assert!(p.matches("/home/user/file.txt"));
    assert!(p.matches("/home/admin/file.txt"));
    assert!(!p.matches("/home/user/other.txt"));
}

#[test]
fn test_question_mark() {
    let p = PathPattern::new("/file?.txt").unwrap();
    assert!(p.matches("/file1.txt"));
    assert!(p.matches("/fileA.txt"));
    assert!(!p.matches("/file12.txt"));
    assert!(!p.matches("/file.txt"));
}

#[test]
fn test_star_doesnt_match_slash() {
    let p = PathPattern::new("/home/*/file.txt").unwrap();
    assert!(p.matches("/home/user/file.txt"));
    assert!(!p.matches("/home/user/docs/file.txt"));
}

#[test]
fn test_double_star_treated_as_single() {
    let p = PathPattern::new("/home/**/file.txt").unwrap();
    // '**' is treated as '*', so it doesn't match across '/'
    assert!(p.matches("/home/user/file.txt"));
    assert!(!p.matches("/home/user/docs/file.txt"));
}

#[test]
fn test_trailing_star() {
    let p = PathPattern::new("/home/user/*").unwrap();
    assert!(p.matches("/home/user/file.txt"));
    assert!(p.matches("/home/user/document.pdf"));
    // Note: "/home/user/" (empty after /) behavior depends on implementation
}

#[test]
fn test_empty_pattern_and_path() {
    let p = PathPattern::new("").unwrap();
    assert!(p.matches(""));
    assert!(!p.matches("/"));
}

// === STRESS TESTS FOR DEEP PATHS ===

#[test]
fn test_very_deep_path_100_levels() {
    // Test 100-level deep path with wildcards
    let pattern_parts: Vec<&str> = (0..100).map(|_| "*").collect();
    let pattern = format!("/{}", pattern_parts.join("/"));

    let path_parts: Vec<String> = (0..100).map(|i| i.to_string()).collect();
    let path = format!("/{}", path_parts.join("/"));

    let p = PathPattern::new(&pattern).unwrap();
    assert!(p.matches(&path), "Should match 100-level deep path");
}

#[test]
fn test_very_deep_path_50_levels() {
    // Test 50-level deep path (would cause stack overflow in recursive version)
    // Using 50 to stay well within MAX_RESOURCE_PATTERN_LENGTH (1024)
    let pattern_parts: Vec<&str> = (0..50).map(|_| "*").collect();
    let pattern = format!("/{}", pattern_parts.join("/"));

    let path_parts: Vec<String> = (0..50).map(|i| format!("d{}", i)).collect();
    let path = format!("/{}", path_parts.join("/"));

    let p = PathPattern::new(&pattern).unwrap();
    assert!(
        p.matches(&path),
        "Should match 50-level deep path without stack overflow"
    );
}

#[test]
fn test_extreme_depth_within_limits() {
    // Test maximum possible depth within MAX_RESOURCE_PATTERN_LENGTH (256)
    // Each segment is "/*" = 2 chars, so max depth ≈ 127
    let depth = 127;
    let pattern_parts: Vec<&str> = (0..depth).map(|_| "*").collect();
    let pattern = format!("/{}", pattern_parts.join("/"));

    let path_parts: Vec<String> = (0..depth).map(|i| format!("s{}", i)).collect();
    let path = format!("/{}", path_parts.join("/"));

    // Verify pattern is within limits
    assert!(
        pattern.len() <= MAX_RESOURCE_PATTERN_LENGTH,
        "Pattern should be within MAX_RESOURCE_PATTERN_LENGTH"
    );

    let p = PathPattern::new(&pattern).unwrap();
    assert!(
        p.matches(&path),
        "Should match maximum-depth path without stack overflow (iterative implementation)"
    );
}

#[test]
fn test_deep_path_with_mixed_wildcards() {
    let p = PathPattern::new("/a/*/b/*/c/*/d/*/e/*/f/*/g/*/h/*").unwrap();
    assert!(p.matches("/a/1/b/2/c/3/d/4/e/5/f/6/g/7/h/8"));
    assert!(!p.matches("/a/1/b/2/c/3/d/4/e/5/f/6/g/7/h/8/i"));
    assert!(!p.matches("/a/1/b/2/c/3/d/4/e/5/f/6/g/7"));
}

#[test]
fn test_many_consecutive_wildcards() {
    let p = PathPattern::new("/*/*/*/*/*/*/*/*/*/*/*").unwrap();
    assert!(p.matches("/a/b/c/d/e/f/g/h/i/j/k"));
    assert!(!p.matches("/a/b/c/d/e/f/g/h/i/j"));
}

#[test]
fn test_star_at_end_matches_multiple_chars() {
    let p = PathPattern::new("/home/user/file*").unwrap();
    assert!(p.matches("/home/user/file"));
    assert!(p.matches("/home/user/file.txt"));
    assert!(p.matches("/home/user/file123.pdf"));
    assert!(!p.matches("/home/user/other"));
}

#[test]
fn test_multiple_stars_in_segment() {
    let p = PathPattern::new("/home/*/file*.txt").unwrap();
    assert!(p.matches("/home/user/file1.txt"));
    assert!(p.matches("/home/admin/fileABC.txt"));
    assert!(!p.matches("/home/user/other.txt"));
}

#[test]
fn test_backtracking_with_star() {
    // Pattern that requires backtracking
    let p = PathPattern::new("/a*/b").unwrap();
    assert!(p.matches("/ab/b"));
    assert!(p.matches("/aaa/b"));
    assert!(p.matches("/axyz/b"));
    assert!(!p.matches("/a/b/b"));
}

#[test]
fn test_complex_backtracking() {
    // Complex pattern requiring multiple backtracks
    let p = PathPattern::new("/*a*b*c*").unwrap();
    assert!(p.matches("/abc"));
    assert!(p.matches("/xaybzc"));
    assert!(p.matches("/aaabbbccc"));
    assert!(!p.matches("/ab"));
    assert!(!p.matches("/ac"));
}

#[test]
fn test_pattern_longer_than_path() {
    let p = PathPattern::new("/a/b/c/d/e").unwrap();
    assert!(!p.matches("/a/b/c"));
}

#[test]
fn test_path_longer_than_pattern() {
    let p = PathPattern::new("/a/b/c").unwrap();
    assert!(!p.matches("/a/b/c/d/e"));
}

#[test]
fn test_only_wildcards() {
    let p = PathPattern::new("*").unwrap();
    assert!(p.matches("anything"));
    assert!(p.matches("file.txt"));
    assert!(!p.matches(""));
}

#[test]
fn test_question_marks_only() {
    let p = PathPattern::new("???").unwrap();
    assert!(p.matches("abc"));
    assert!(p.matches("123"));
    assert!(!p.matches("ab"));
    assert!(!p.matches("abcd"));
}

#[test]
fn test_utf8_paths() {
    let p = PathPattern::new("/home/*/файл.txt").unwrap();
    assert!(p.matches("/home/user/файл.txt"));
    assert!(!p.matches("/home/user/file.txt"));
}

#[test]
fn test_special_chars_in_path() {
    let p = PathPattern::new("/home/user/*.txt").unwrap();
    assert!(p.matches("/home/user/file-name.txt"));
    assert!(p.matches("/home/user/file_name.txt"));
    assert!(p.matches("/home/user/file.name.txt"));
}

#[test]
fn test_max_pattern_length_enforcement() {
    let long_pattern = "a".repeat(MAX_RESOURCE_PATTERN_LENGTH + 1);
    let result = PathPattern::new(long_pattern);
    assert!(result.is_err());

    if let Err(PolicyError::PatternTooLong { max, length }) = result {
        assert_eq!(max, MAX_RESOURCE_PATTERN_LENGTH);
        assert_eq!(length, MAX_RESOURCE_PATTERN_LENGTH + 1);
    } else {
        panic!("Expected PatternTooLong error");
    }
}

#[test]
fn test_edge_case_star_before_slash() {
    let p = PathPattern::new("*/file.txt").unwrap();
    assert!(p.matches("dir/file.txt"));
    assert!(!p.matches("dir/subdir/file.txt"));
}

#[test]
fn test_edge_case_multiple_slashes() {
    let p = PathPattern::new("/home//user").unwrap();
    assert!(p.matches("/home//user"));
    assert!(!p.matches("/home/user"));
}
