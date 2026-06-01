#![forbid(unsafe_code)]

//! ECDSA over NIST P-256 (secp256r1) signature wrappers for the OxiCrypto stack.
//!
//! Keys are provided as raw 32-byte scalars (signing) or SEC1-encoded bytes
//! (compressed 33 bytes, or uncompressed 65 bytes) for verifying.

use oxicrypto_core::{CryptoError, Vec};
use p256::ecdsa::{
    signature::{Signer as EcdsaSigner, Verifier as EcdsaVerifier},
    Signature, SigningKey, VerifyingKey,
};

/// ECDSA P-256 signing key.
///
/// Construct via [`EcdsaP256Signer::from_bytes`] using the raw 32-byte scalar.
pub struct EcdsaP256Signer {
    signing_key: SigningKey,
}

impl EcdsaP256Signer {
    /// Construct from 32-byte raw scalar bytes.
    pub fn from_bytes(scalar: &[u8]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_slice(scalar).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { signing_key })
    }

    /// Sign `message` (prehash performed internally by the SHA-256 digest) and return
    /// DER-encoded signature bytes.
    #[must_use = "signature result must be checked"]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig: Signature = EcdsaSigner::sign(&self.signing_key, message);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// Return the corresponding verifying key as compressed SEC1 bytes (33 bytes).
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }
}

/// ECDSA P-256 verifying key.
pub struct EcdsaP256Verifier {
    verifying_key: VerifyingKey,
}

impl EcdsaP256Verifier {
    /// Construct from SEC1-encoded public key bytes (compressed 33 bytes or uncompressed 65 bytes).
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let verifying_key =
            VerifyingKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { verifying_key })
    }

    /// Verify DER-encoded `signature` over `message`.
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = Signature::from_der(signature).map_err(|_| CryptoError::InvalidTag)?;
        EcdsaVerifier::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}
