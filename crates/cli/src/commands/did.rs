use crate::keystore::Keystore;
use colored::*;
use core_identity::Identity;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize)]
struct IdentityExport {
    did: String,
    public_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
}

pub fn new(output_path: Option<&str>, unsafe_show_secret: bool) -> anyhow::Result<()> {
    println!("{}", "Generating new DID...".bold());

    // Generate identity
    let mut rng = rand::thread_rng();
    let identity = Identity::generate(&mut rng)?;

    // Get DID components
    let public_key_hash = hex::encode(identity.public_key_hash());
    let did = format!("did:p47h:{}", public_key_hash);

    println!("  {} DID: {}", "✓".green(), did.cyan());
    println!("  {} Public Key Hash: {}", "✓".green(), public_key_hash);

    // Handle secret key
    use secrecy::ExposeSecret;
    let secret_bytes = identity.signing_key_bytes();
    let secret_hex = hex::encode(secret_bytes.expose_secret());

    if let Some(path) = output_path {
        // Export to specified file
        let export = IdentityExport {
            did: did.clone(),
            public_key_hash: public_key_hash.clone(),
            secret_key: Some(secret_hex.clone()),
        };

        let json = serde_json::to_string_pretty(&export)?;

        // Prompt for password to encrypt
        println!();
        println!("{}", "[*] Securing Identity".bold());
        let password = dialoguer::Password::new()
            .with_prompt("Enter a passphrase to encrypt this identity")
            .with_confirmation("Confirm passphrase", "Passphrases mismatch")
            .interact()?;

        let encrypted = crate::crypto::encrypt(json.as_bytes(), &password)?;
        let encrypted_json = serde_json::to_string_pretty(&encrypted)?;

        fs::write(path, encrypted_json)?;

        println!();
        println!(
            "{} Encrypted identity exported to: {}",
            "✓".green().bold(),
            path
        );
        println!(
            "{} Keep this file secure! You will need the passphrase to use it.",
            "⚠".yellow().bold()
        );
    } else {
        // Save to secure keystore (default)
        let keystore = Keystore::new(Keystore::default_path());

        let export = IdentityExport {
            did: did.clone(),
            public_key_hash: public_key_hash.clone(),
            secret_key: Some(secret_hex.clone()),
        };

        let json = serde_json::to_string_pretty(&export)?;

        println!();
        println!("{}", "[*] Securing Keystore".bold());
        let password = dialoguer::Password::new()
            .with_prompt("Enter a passphrase to encrypt your default identity")
            .with_confirmation("Confirm passphrase", "Passphrases mismatch")
            .interact()?;

        let encrypted = crate::crypto::encrypt(json.as_bytes(), &password)?;
        let encrypted_json = serde_json::to_string_pretty(&encrypted)?;

        keystore.save(&encrypted_json)?;

        println!();
        println!(
            "{} Identity saved to: {}",
            "✓".green().bold(),
            keystore.path().display()
        );
        println!(
            "{} File permissions: 600 (owner read/write only)",
            "*".green()
        );
    }

    // Only show secret if explicitly requested with unsafe flag
    if unsafe_show_secret {
        println!();
        println!(
            "{}",
            "[!] UNSAFE MODE - SECRET KEY EXPOSED [!]".red().bold()
        );
        println!("Secret Key: {}", secret_hex);
        println!("{}", "[!] DO NOT SHARE THIS KEY [!]".red().bold());
    } else {
        println!();
        println!("{} Secret key saved securely (not displayed)", "ℹ".blue());
    }

    Ok(())
}
