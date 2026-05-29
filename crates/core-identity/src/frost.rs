//! FROST-Ed25519 threshold signing module.
//!
//! Provides t-of-n threshold signing where `t` participants must cooperate
//! to produce a valid Ed25519 signature. The resulting signature is
//! indistinguishable from a regular Ed25519 signature — verifiers use
//! the group public key exactly like a single-signer key.
//!
//! # Protocol overview
//!
//! 1. **DKG** (Distributed Key Generation): participants jointly generate
//!    key shares without any single party learning the full secret key.
//! 2. **Commitment round**: each signer generates and shares a nonce commitment.
//! 3. **Signing round**: each signer produces a signature share using the
//!    aggregated commitments and their key share.
//! 4. **Aggregation**: a coordinator combines `t` signature shares into
//!    a single valid Ed25519 signature.
//!
//! # Security notes
//!
//! - The full secret key never exists in any single location.
//! - Key shares must be stored securely (encrypted at rest, zeroized on drop).
//! - The DKG ceremony must happen over an authenticated channel.

use crate::error::{IdentityError, Result};
use alloc::collections::BTreeMap;
use alloc::format;
use ed25519_dalek::{Signature, VerifyingKey};

pub use frost_ed25519 as frost;
use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage},
    Identifier,
};

/// Configuration for a FROST threshold signing group.
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    pub min_signers: u16,
    pub max_signers: u16,
}

impl ThresholdConfig {
    pub fn new(min_signers: u16, max_signers: u16) -> Result<Self> {
        if min_signers < 2 {
            return Err(IdentityError::InvalidState(
                "Threshold must be at least 2".into(),
            ));
        }
        if min_signers > max_signers {
            return Err(IdentityError::InvalidState(
                "min_signers must be <= max_signers".into(),
            ));
        }
        Ok(Self {
            min_signers,
            max_signers,
        })
    }
}

/// Result of a DKG ceremony: each participant receives a KeyPackage,
/// and all participants share the PublicKeyPackage.
#[derive(Clone)]
pub struct DkgOutput {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub public_key_package: PublicKeyPackage,
}

impl DkgOutput {
    /// Extract the group verifying key (usable as a standard Ed25519 public key).
    pub fn group_verifying_key(&self) -> Result<VerifyingKey> {
        let frost_vk = self.public_key_package.verifying_key();
        let bytes = frost_vk
            .serialize()
            .map_err(|e| IdentityError::InvalidState(format!("Serialization error: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::InvalidPublicKey)
    }
}

/// Run a trusted-dealer DKG (suitable for single-server setups or testing).
///
/// In production, use a distributed DKG protocol (e.g., Pedersen DKG)
/// where no single party learns the full secret.
pub fn trusted_dealer_dkg(config: &ThresholdConfig) -> Result<DkgOutput> {
    let rng = rand::rngs::OsRng;
    let (shares, pubkeys) = frost_ed25519::keys::generate_with_dealer(
        config.max_signers,
        config.min_signers,
        frost_ed25519::keys::IdentifierList::Default,
        rng,
    )
    .map_err(|e| IdentityError::InvalidState(format!("DKG failed: {e}")))?;

    let mut key_packages = BTreeMap::new();
    for (id, share) in shares {
        let kp = KeyPackage::try_from(share)
            .map_err(|e| IdentityError::InvalidState(format!("KeyPackage error: {e}")))?;
        key_packages.insert(id, kp);
    }

    Ok(DkgOutput {
        key_packages,
        public_key_package: pubkeys,
    })
}

/// Coordinator for a single FROST signing round.
///
/// Orchestrates the commit→sign→aggregate flow for a given message.
pub struct SigningCoordinator {
    public_key_package: PublicKeyPackage,
    min_signers: u16,
}

impl SigningCoordinator {
    pub fn new(public_key_package: PublicKeyPackage, min_signers: u16) -> Self {
        Self {
            public_key_package,
            min_signers,
        }
    }

    /// Execute a complete signing round given `t` key packages and a message.
    ///
    /// This is a simplified single-process flow for local signing.
    /// A distributed signing flow would split commit/sign across network messages.
    pub fn sign(
        &self,
        key_packages: &BTreeMap<Identifier, KeyPackage>,
        message: &[u8],
    ) -> Result<Signature> {
        if (key_packages.len() as u16) < self.min_signers {
            return Err(IdentityError::InvalidState(format!(
                "Need at least {} signers, got {}",
                self.min_signers,
                key_packages.len()
            )));
        }

        let mut rng = rand::rngs::OsRng;

        // Round 1: generate nonces and commitments
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        for (&id, key_package) in key_packages {
            let (nonces, commitments) =
                frost_ed25519::round1::commit(key_package.signing_share(), &mut rng);
            nonces_map.insert(id, nonces);
            commitments_map.insert(id, commitments);
        }

        // Build signing package
        let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message);

        // Round 2: generate signature shares
        let mut signature_shares = BTreeMap::new();
        for (&id, key_package) in key_packages {
            let nonces = &nonces_map[&id];
            let share = frost_ed25519::round2::sign(&signing_package, nonces, key_package)
                .map_err(|e| IdentityError::InvalidState(format!("Signing failed: {e}")))?;
            signature_shares.insert(id, share);
        }

        // Aggregate
        let group_signature = frost_ed25519::aggregate(
            &signing_package,
            &signature_shares,
            &self.public_key_package,
        )
        .map_err(|e| IdentityError::InvalidState(format!("Aggregation failed: {e}")))?;

        let sig_bytes = group_signature
            .serialize()
            .map_err(|e| IdentityError::InvalidState(format!("Signature serialization: {e}")))?;
        Signature::from_slice(&sig_bytes).map_err(|_| IdentityError::InvalidSignature)
    }

    pub fn group_verifying_key(&self) -> Result<VerifyingKey> {
        let bytes = self
            .public_key_package
            .verifying_key()
            .serialize()
            .map_err(|e| IdentityError::InvalidState(format!("Serialization error: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::InvalidPublicKey)
    }
}

/// FROST-backed TrustAnchorSigner for local (single-process) threshold signing.
///
/// Holds `t` key shares and orchestrates the signing protocol internally.
/// For distributed signing across network participants, use `SigningCoordinator`
/// with a network transport layer.
pub struct FrostLocalSigner {
    coordinator: SigningCoordinator,
    key_packages: BTreeMap<Identifier, KeyPackage>,
}

impl FrostLocalSigner {
    pub fn from_dkg(dkg: DkgOutput, min_signers: u16) -> Self {
        let coordinator =
            SigningCoordinator::new(dkg.public_key_package, min_signers);
        Self {
            coordinator,
            key_packages: dkg.key_packages,
        }
    }
}

impl crate::trust_anchor::TrustAnchorSigner for FrostLocalSigner {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        self.coordinator.sign(&self.key_packages, message)
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.coordinator
            .group_verifying_key()
            .expect("group key should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_anchor::{Ed25519Verifier, TrustAnchorSigner, TrustAnchorVerifier};

    #[test]
    fn frost_2_of_3_sign_and_verify() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let dkg = trusted_dealer_dkg(&config).unwrap();

        let group_vk = dkg.group_verifying_key().unwrap();

        // Use only 2 of 3 shares
        let subset: BTreeMap<_, _> = dkg.key_packages.iter().take(2).map(|(&k, v)| (k, v.clone())).collect();

        let coordinator = SigningCoordinator::new(dkg.public_key_package.clone(), 2);
        let message = b"threshold signed policy update";
        let signature = coordinator.sign(&subset, message).unwrap();

        let verifier = Ed25519Verifier::new(group_vk);
        assert!(verifier.verify(message, &signature).is_ok());
    }

    #[test]
    fn frost_local_signer_implements_trait() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let dkg = trusted_dealer_dkg(&config).unwrap();
        let group_vk = dkg.group_verifying_key().unwrap();

        let signer = FrostLocalSigner::from_dkg(dkg, 2);

        let message = b"policy data to sign with frost";
        let signature = signer.sign(message).unwrap();

        let verifier = Ed25519Verifier::new(group_vk);
        assert!(verifier.verify(message, &signature).is_ok());
    }

    #[test]
    fn frost_rejects_wrong_message() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let dkg = trusted_dealer_dkg(&config).unwrap();
        let group_vk = dkg.group_verifying_key().unwrap();

        let signer = FrostLocalSigner::from_dkg(dkg, 2);
        let signature = signer.sign(b"correct message").unwrap();

        let verifier = Ed25519Verifier::new(group_vk);
        assert!(verifier.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn frost_insufficient_signers_rejected() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let dkg = trusted_dealer_dkg(&config).unwrap();

        // Only 1 signer (below threshold of 2)
        let subset: BTreeMap<_, _> = dkg.key_packages.iter().take(1).map(|(&k, v)| (k, v.clone())).collect();

        let coordinator = SigningCoordinator::new(dkg.public_key_package, 2);
        let err = coordinator.sign(&subset, b"message");
        assert!(err.is_err());
    }

    #[test]
    fn frost_config_validation() {
        assert!(ThresholdConfig::new(1, 3).is_err());
        assert!(ThresholdConfig::new(3, 2).is_err());
        assert!(ThresholdConfig::new(2, 3).is_ok());
        assert!(ThresholdConfig::new(3, 5).is_ok());
    }
}
