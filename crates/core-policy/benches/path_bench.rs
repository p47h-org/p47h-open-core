use core_policy::PathPattern;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

/// Generate a deep path pattern with wildcards
fn generate_deep_pattern(depth: usize) -> String {
    let parts: Vec<&str> = (0..depth).map(|_| "*").collect();
    format!("/{}", parts.join("/"))
}

/// Generate a deep path with numeric segments
fn generate_deep_path(depth: usize) -> String {
    let parts: Vec<String> = (0..depth).map(|i| format!("d{}", i)).collect();
    format!("/{}", parts.join("/"))
}

fn benchmark_deep_path_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_matching_depth");

    // MAX_RESOURCE_PATTERN_LENGTH = 256, so max depth ≈ 128 (2 chars per segment)
    for depth in [10, 50, 100, 127].iter() {
        let pattern = generate_deep_pattern(*depth);
        let path = generate_deep_path(*depth);

        // Skip if pattern exceeds limit
        if let Ok(p) = PathPattern::new(&pattern) {
            group.bench_with_input(BenchmarkId::from_parameter(depth), depth, |b, _| {
                b.iter(|| p.matches(black_box(&path)));
            });
        }
    }

    group.finish();
}

fn benchmark_wildcard_backtracking(c: &mut Criterion) {
    // Pattern that requires heavy backtracking
    let p = PathPattern::new("/*a*b*c*d*e*f*g*h*").unwrap();

    c.bench_function("backtracking_worst_case", |b| {
        b.iter(|| {
            p.matches(black_box(
                "/xxxxxxxxxxxxxxxxabcdefghxxxxxxxxxxxxxxxxabcdefgh",
            ))
        });
    });
}

fn benchmark_simple_patterns(c: &mut Criterion) {
    let exact = PathPattern::new("/home/user/file.txt").unwrap();
    let single_wildcard = PathPattern::new("/home/*/file.txt").unwrap();
    let trailing_wildcard = PathPattern::new("/home/user/*").unwrap();

    c.bench_function("exact_match", |b| {
        b.iter(|| exact.matches(black_box("/home/user/file.txt")));
    });

    c.bench_function("single_wildcard", |b| {
        b.iter(|| single_wildcard.matches(black_box("/home/admin/file.txt")));
    });

    c.bench_function("trailing_wildcard", |b| {
        b.iter(|| trailing_wildcard.matches(black_box("/home/user/document.pdf")));
    });
}

fn benchmark_complex_patterns(c: &mut Criterion) {
    let p = PathPattern::new("/a/*/b/*/c/*/d/*/e/*/f/*/g/*/h/*").unwrap();

    c.bench_function("complex_mixed_wildcards", |b| {
        b.iter(|| p.matches(black_box("/a/1/b/2/c/3/d/4/e/5/f/6/g/7/h/8")));
    });
}

criterion_group!(
    benches,
    benchmark_deep_path_matching,
    benchmark_wildcard_backtracking,
    benchmark_simple_patterns,
    benchmark_complex_patterns
);
criterion_main!(benches);
