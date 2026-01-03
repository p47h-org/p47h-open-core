use core_policy::{Action, Policy, PolicyRule, Resource};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn create_test_policy(num_rules: usize) -> Policy {
    let mut policy = Policy::new_unversioned("benchmark-policy").unwrap();

    for i in 0..num_rules {
        let rule = PolicyRule::new(
            format!("did:p47h:peer{}", i),
            Action::Read,
            Resource::File(format!("/data/file{}.txt", i)),
        );
        policy = policy.add_rule(rule).unwrap();
    }

    policy
}

fn benchmark_policy_evaluation(c: &mut Criterion) {
    let policy_10 = create_test_policy(10);
    let policy_100 = create_test_policy(100);
    let policy_1000 = create_test_policy(1000);

    c.bench_function("policy_eval_10_rules", |b| {
        b.iter(|| {
            policy_10.is_allowed(
                black_box("did:p47h:peer5"),
                black_box(&Action::Read),
                black_box(&Resource::File("/data/file5.txt".to_string())),
            )
        });
    });

    c.bench_function("policy_eval_100_rules", |b| {
        b.iter(|| {
            policy_100.is_allowed(
                black_box("did:p47h:peer50"),
                black_box(&Action::Read),
                black_box(&Resource::File("/data/file50.txt".to_string())),
            )
        });
    });

    c.bench_function("policy_eval_1000_rules", |b| {
        b.iter(|| {
            policy_1000.is_allowed(
                black_box("did:p47h:peer500"),
                black_box(&Action::Read),
                black_box(&Resource::File("/data/file500.txt".to_string())),
            )
        });
    });
}

fn benchmark_policy_creation(c: &mut Criterion) {
    c.bench_function("policy_create_empty", |b| {
        b.iter(|| Policy::new_unversioned(black_box("test-policy")));
    });

    c.bench_function("policy_add_rule", |b| {
        let mut policy = Policy::new_unversioned("test").unwrap();
        b.iter(|| {
            let rule = PolicyRule::new(
                black_box("did:p47h:test".to_string()),
                black_box(Action::Read),
                black_box(Resource::File("/test".to_string())),
            );
            policy = policy.clone().add_rule(rule).unwrap();
        });
    });
}

criterion_group!(
    benches,
    benchmark_policy_evaluation,
    benchmark_policy_creation
);
criterion_main!(benches);
