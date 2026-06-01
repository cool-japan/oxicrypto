#![forbid(unsafe_code)]

//! Ed448 signature wrappers for the OxiCrypto stack.
//!
//! Backed by `ed448-goldilocks` (Pure Rust, no unsafe, no FFI).
//! Secret keys are 57-byte raw seeds; public keys are 57-byte compressed Edwards points.
//! Signatures are 114 bytes.

use ed448_goldilocks::{
    signature::{Signer as Ed448Signer, Verifier as Ed448Verifier},
    EdwardsScalarBytes, Signature, SigningKey, VerifyingKey,
};
use oxicrypto_core::{CryptoError, Vec};

/// Ed448 signing key.
///
/// The secret key is a 57-byte raw seed (RFC 8032 §5.2.5 encoding).
pub struct Ed448SigningKey {
    signing_key: SigningKey,
}

impl Ed448SigningKey {
    /// Construct from a 57-byte raw seed.
    pub fn from_bytes(seed: &[u8]) -> Result<Self, CryptoError> {
        let sk_bytes: [u8; 57] = seed.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let scalar = EdwardsScalarBytes::from(sk_bytes);
        Ok(Self {
            signing_key: SigningKey::from(scalar),
        })
    }

    /// Sign `message` and return the 114-byte raw signature.
    #[must_use = "signature result must be checked"]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig: Signature = Ed448Signer::sign(&self.signing_key, message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Return the corresponding 57-byte verifying key (compressed Edwards-y).
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 57] {
        let vk: VerifyingKey = self.signing_key.verifying_key();
        *vk.as_bytes()
    }
}

/// Ed448 verifying key.
pub struct Ed448VerifyingKey {
    verifying_key: VerifyingKey,
}

impl Ed448VerifyingKey {
    /// Construct from 57-byte compressed public key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let pk_bytes: &[u8; 57] = bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(pk_bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { verifying_key })
    }

    /// Verify 114-byte `signature` over `message`.
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig_bytes: [u8; 114] = signature.try_into().map_err(|_| CryptoError::InvalidTag)?;
        let sig = Signature::from_bytes(&sig_bytes);
        Ed448Verifier::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}
