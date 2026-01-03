//! Simple Authorization Flow Example
//!
//! This example demonstrates the core authorization workflow in p47h:
//!
//! 1. Create a cryptographic identity (Ed25519 keypair)
//! 2. Define a policy with multiple rules
//! 3. Use the PolicyAuthorizer to evaluate access requests
//!
//! Run with: cargo run --example simple_auth_flow

use core_identity::Identity;
use core_policy::{Action, Policy, PolicyAuthorizer, PolicyRule, Resource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("p47h Open Core - Simple Authorization Flow");
    println!("-------------------------------------------");
    println!();

    // -------------------------------------------------------------------------
    // Step 1: Create Identities
    // -------------------------------------------------------------------------
    // Each user or device in the network has a unique cryptographic identity.
    // The identity is an Ed25519 keypair. We use the public key hash as the
    // peer identifier for policy rules.

    let mut rng = rand::thread_rng();

    let alice = Identity::generate(&mut rng)?;
    let alice_id = format!("alice-{}", hex::encode(&alice.public_key_hash()[..4]));

    let bob = Identity::generate(&mut rng)?;
    let bob_id = format!("bob-{}", hex::encode(&bob.public_key_hash()[..4]));

    println!("Created identities:");
    println!("  Alice: {}", alice_id);
    println!("  Bob:   {}", bob_id);
    println!();

    // -------------------------------------------------------------------------
    // Step 2: Define a Policy
    // -------------------------------------------------------------------------
    // A policy is a collection of rules that define who can do what on which
    // resources. Each rule specifies:
    //   - peer_id: The identity this rule applies to
    //   - action: What operation is allowed (Read, Write, Execute, Delete, All)
    //   - resource: What resource pattern this applies to (supports wildcards)

    // Policy parameters:
    //   - name: Human-readable identifier
    //   - valid_duration: How long the policy is valid (in seconds)
    //   - current_time: Unix timestamp when the policy was created
    let current_time = 1700000000; // Fixed timestamp for reproducibility
    let valid_duration = 86400; // 24 hours

    let policy = Policy::new("file-access-policy", valid_duration, current_time)?
        // Rule 1: Alice can read any file under /data/
        .add_rule(PolicyRule::new(
            alice_id.clone(),
            Action::Read,
            Resource::File("/data/*".into()),
        ))?
        // Rule 2: Alice can write to her personal directory
        .add_rule(PolicyRule::new(
            alice_id.clone(),
            Action::Write,
            Resource::File("/home/alice/*".into()),
        ))?
        // Rule 3: Bob has full access to the /shared/ directory
        .add_rule(PolicyRule::new(
            bob_id.clone(),
            Action::All,
            Resource::File("/shared/*".into()),
        ))?;

    println!("Created policy: {}", policy.name());
    println!("  Rules: {}", policy.rules().len());
    println!("  Valid until: {} (Unix timestamp)", policy.valid_until());
    println!();

    // -------------------------------------------------------------------------
    // Step 3: Evaluate Access Requests
    // -------------------------------------------------------------------------
    // The PolicyAuthorizer evaluates whether a specific peer can perform a
    // specific action on a specific resource. It checks all rules and returns
    // true if at least one rule allows the access.

    let authorizer = PolicyAuthorizer::new(policy.rules());

    // Define test cases: (peer, action, resource, expected_result)
    let test_cases = [
        // Alice reading from /data/ - should be ALLOWED (Rule 1)
        (&alice_id, Action::Read, "/data/report.txt", true),
        // Alice writing to /data/ - should be DENIED (no rule allows this)
        (&alice_id, Action::Write, "/data/report.txt", false),
        // Alice writing to her home - should be ALLOWED (Rule 2)
        (&alice_id, Action::Write, "/home/alice/notes.txt", true),
        // Bob reading from /data/ - should be DENIED (no rule for Bob on /data/)
        (&bob_id, Action::Read, "/data/report.txt", false),
        // Bob writing to /shared/ - should be ALLOWED (Rule 3, Action::All)
        (&bob_id, Action::Write, "/shared/document.pdf", true),
        // Bob deleting from /shared/ - should be ALLOWED (Rule 3, Action::All)
        (&bob_id, Action::Delete, "/shared/old-file.txt", true),
        // Unknown user - should be DENIED (no rules match)
        (&"unknown-user".to_string(), Action::Read, "/data/file.txt", false),
    ];

    println!("Evaluating access requests:");
    println!();

    for (peer_id, action, resource_path, expected) in test_cases {
        let resource = Resource::File(resource_path.into());
        let allowed = authorizer.is_allowed(peer_id, &action, &resource);

        // Verify our expectations match the actual result
        let status = if allowed { "ALLOWED" } else { "DENIED" };
        let check = if allowed == expected { "OK" } else { "MISMATCH" };

        println!(
            "  {} {:?} {} -> {} [{}]",
            peer_id, action, resource_path, status, check
        );
    }

    println!();
    println!("-------------------------------------------");
    println!("Authorization flow completed successfully.");

    Ok(())
}
