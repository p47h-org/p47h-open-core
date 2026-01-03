use colored::*;
use core_policy::Policy;
use std::fs;

pub fn check(file_path: &str) -> anyhow::Result<()> {
    println!("{} {}", "Checking policy:".bold(), file_path);

    // Read file
    let content =
        fs::read_to_string(file_path).map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

    // Parse TOML
    let policy: Policy =
        toml::from_str(&content).map_err(|e| anyhow::anyhow!("TOML parsing error: {}", e))?;

    // Validate policy structure
    println!("  {} Policy name: {}", "✓".green(), policy.name());
    println!("  {} Version: {}", "✓".green(), policy.version());
    println!("  {} Rules: {}", "✓".green(), policy.rules().len());
    println!("  {} Valid until: {}", "✓".green(), policy.valid_until());

    // Check for potential issues
    let mut warnings = 0;

    // Check for duplicate rules
    let mut seen_rules = std::collections::HashSet::new();
    for (i, rule) in policy.rules().iter().enumerate() {
        let rule_key = format!("{:?}:{:?}:{:?}", rule.peer_id, rule.action, rule.resource);
        if !seen_rules.insert(rule_key.clone()) {
            println!("  {} Rule {} is a duplicate", "⚠".yellow(), i + 1);
            warnings += 1;
        }
    }

    // Summary
    println!();
    if warnings == 0 {
        println!("{} Policy is valid!", "✓".green().bold());
    } else {
        println!(
            "{} Policy is valid with {} warning(s)",
            "⚠".yellow().bold(),
            warnings
        );
    }

    Ok(())
}
