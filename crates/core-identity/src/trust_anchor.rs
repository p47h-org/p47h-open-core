//! Trust Anchor signing and verification abstractions.
//!
//! These traits decouple policy signing from the concrete key scheme,
//! allowing a future migration from single-key Ed25519 to FROST
//! threshold signing without changing the verification path.
//!
//! A FROST-Ed25519 aggregated signature is indistinguishable from a
//! regular Ed25519 signature at the verifier side — the group public
//! key is a standard Ed25519 point. This means `TrustAnchorVerifier`
//! works identically for both backends.

use crate::error::{IdentityError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

/// Signs messages on behalf of the Trust Anchor.
///
/// Implementations:
/// - [`Ed25519SingleSigner`]: single-key Ed25519 (current production path)
/// - `FrostThresholdSigner` (H1): t-of-n threshold signing via FROST-Ed25519
///
/// # Limitations
///
/// This trait assumes synchronous, single-call signing. FROST threshold
/// signing is an interactive multi-round protocol that cannot be expressed
/// as a simple `sign(&self, message) -> Signature` call. The H1
/// implementation will require a redesigned async/stateful signing API
/// for the FROST path; this trait will remain valid for the single-key
/// backend and for the verification side (which is identical for both).
pub trait TrustAnchorSigner {
    /// Sign `message` and return an Ed25519-compatible signature.
    fn sign(&self, message: &[u8]) -> Result<Signature>;

    /// The public verification key (group key for FROST, normal key for single).
    fn verifying_key(&self) -> VerifyingKey;
}

/// Verifies Trust Anchor signatures.
///
/// Because FROST-Ed25519 produces standard Ed25519 signatures, this
/// trait has a single implementation that works for both backends.
pub trait TrustAnchorVerifier {
    /// Verify `signature` over `message` against the Trust Anchor public key.
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()>;
}

/// Single-key Ed25519 signer (current production backend).
pub struct Ed25519SingleSigner {
    signing_key: SigningKey,
}

impl Ed25519SingleSigner {
    /// Create from an existing signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Create from raw 32-byte seed (zeroized after key derivation).
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing_key }
    }
}

impl TrustAnchorSigner for Ed25519SingleSigner {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(self.signing_key.sign(message))
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Ed25519 signature verifier (works for both single-key and FROST).
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Create from a public key.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self { verifying_key: key })
    }
}

impl TrustAnchorVerifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

/// Deprecated placeholder — use `frost::FrostLocalSigner` (behind `frost` feature) instead.
#[deprecated(since = "0.10.3", note = "Use frost::FrostLocalSigner with the `frost` feature flag")]
pub struct FrostThresholdSigner {
    pub t: u16,
    pub n: u16,
}

#[allow(deprecated)]
impl TrustAnchorSigner for FrostThresholdSigner {
    fn sign(&self, _message: &[u8]) -> Result<Signature> {
        unimplemented!("Use frost::FrostLocalSigner with the `frost` feature flag")
    }

    fn verifying_key(&self) -> VerifyingKey {
        unimplemented!("Use frost::FrostLocalSigner with the `frost` feature flag")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_single_roundtrip() {
        let signer = Ed25519SingleSigner::from_seed([42u8; 32]);
        let message = b"policy data to sign";
        let signature = signer.sign(message).unwrap();

        let verifier = Ed25519Verifier::new(signer.verifying_key());
        assert!(verifier.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_ed25519_rejects_wrong_message() {
        let signer = Ed25519SingleSigner::from_seed([42u8; 32]);
        let signature = signer.sign(b"correct message").unwrap();

        let verifier = Ed25519Verifier::new(signer.verifying_key());
        assert!(verifier.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_ed25519_rejects_wrong_key() {
        let signer = Ed25519SingleSigner::from_seed([42u8; 32]);
        let signature = signer.sign(b"message").unwrap();

        let other = Ed25519SingleSigner::from_seed([99u8; 32]);
        let verifier = Ed25519Verifier::new(other.verifying_key());
        assert!(verifier.verify(b"message", &signature).is_err());
    }
}
