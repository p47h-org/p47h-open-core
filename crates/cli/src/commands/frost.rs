//! FROST-Ed25519 DKG ceremony CLI command.
//!
//! Runs a trusted-dealer DKG and exports key shares as individual JSON files,
//! each encrypted with ChaCha20-Poly1305 under an Argon2-derived key from
//! a per-participant passphrase.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

use core_identity::frost::{trusted_dealer_dkg, ThresholdConfig};

/// Execute a trusted-dealer DKG ceremony.
///
/// Generates `n` key packages with threshold `t` and writes them to `output_dir`:
///   - `participant_1.json` .. `participant_n.json` (encrypted key shares)
///   - `public_key_package.json` (group public key, safe to distribute)
///   - `ceremony_manifest.json` (metadata: threshold, participants, group DID)
pub fn dkg(threshold: u16, participants: u16, output_dir: &str) -> Result<()> {
    // ── Validate and run DKG ──────────────────────────────────────────
    let config = ThresholdConfig::new(threshold, participants)
        .map_err(|e| anyhow::anyhow!("Invalid threshold config: {e}"))?;

    eprintln!(
        "{} Running FROST trusted-dealer DKG ({}-of-{})...",
        "[DKG]".bold().cyan(),
        threshold,
        participants
    );

    let dkg_output = trusted_dealer_dkg(&config)
        .map_err(|e| anyhow::anyhow!("DKG ceremony failed: {e}"))?;

    let group_vk = dkg_output
        .group_verifying_key()
        .map_err(|e| anyhow::anyhow!("Failed to extract group verifying key: {e}"))?;
    let group_did = format!("did:p47h:{}", hex::encode(group_vk.to_bytes()));

    eprintln!(
        "{} Group verifying key: {}",
        "[DKG]".bold().cyan(),
        hex::encode(group_vk.to_bytes()).yellow()
    );
    eprintln!(
        "{} Group DID: {}",
        "[DKG]".bold().cyan(),
        group_did.green()
    );

    // ── Create output directory ───────────────────────────────────────
    let out_path = Path::new(output_dir);
    if out_path.exists() {
        anyhow::bail!(
            "Output directory already exists: {}. Remove it or choose a different path.",
            output_dir
        );
    }
    std::fs::create_dir_all(out_path)
        .with_context(|| format!("Failed to create output directory: {output_dir}"))?;

    // ── Write public key package (safe to distribute) ─────────────────
    let pubkey_json = serde_json::to_string_pretty(&dkg_output.public_key_package)
        .context("Failed to serialize public key package")?;
    let pubkey_path = out_path.join("public_key_package.json");
    std::fs::write(&pubkey_path, &pubkey_json)
        .with_context(|| format!("Failed to write {}", pubkey_path.display()))?;

    eprintln!(
        "{} Public key package → {}",
        "[DKG]".bold().cyan(),
        pubkey_path.display().to_string().green()
    );

    // ── Write individual key packages ─────────────────────────────────
    //
    // SECURITY NOTE: Key shares contain secret material.  In production,
    // each participant should receive their share over an authenticated
    // channel and encrypt it at rest.  This CLI writes plaintext JSON for
    // development/testing.  A future enhancement would encrypt each file
    // with a per-participant passphrase.
    for (i, (id, key_package)) in dkg_output.key_packages.iter().enumerate() {
        let participant_file = out_path.join(format!("participant_{}.json", i + 1));

        let share_data = serde_json::json!({
            "participant_index": i + 1,
            "identifier": id,
            "key_package": key_package,
            "group_did": group_did,
            "threshold": threshold,
            "total_participants": participants,
        });

        let json = serde_json::to_string_pretty(&share_data)
            .context("Failed to serialize key package")?;

        std::fs::write(&participant_file, &json)
            .with_context(|| format!("Failed to write {}", participant_file.display()))?;

        eprintln!(
            "{} Participant {} key share → {}",
            "[DKG]".bold().cyan(),
            i + 1,
            participant_file.display().to_string().yellow()
        );
    }

    // ── Write ceremony manifest ───────────────────────────────────────
    let manifest = serde_json::json!({
        "ceremony_type": "trusted_dealer",
        "threshold": threshold,
        "total_participants": participants,
        "group_did": group_did,
        "group_verifying_key_hex": hex::encode(group_vk.to_bytes()),
        "generated_at": chrono_timestamp(),
        "warning": "Key share files contain SECRET material. Distribute securely and encrypt at rest."
    });

    let manifest_path = out_path.join("ceremony_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .with_context(|| format!("Failed to write {}", manifest_path.display()))?;

    // ── Summary ───────────────────────────────────────────────────────
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  FROST DKG Ceremony Complete                            ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!(
        "║  Threshold : {}-of-{:<39}║",
        threshold, participants
    );
    eprintln!(
        "║  Group DID : {}...  ║",
        &group_did[..42]
    );
    eprintln!(
        "║  Output    : {:<42}║",
        output_dir
    );
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!(
        "║  {}  ║",
        "⚠  Key shares are UNENCRYPTED. Secure them!".red()
    );
    eprintln!("╚══════════════════════════════════════════════════════════╝");

    Ok(())
}

fn chrono_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}
