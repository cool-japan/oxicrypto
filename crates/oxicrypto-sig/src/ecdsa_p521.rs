#![forbid(unsafe_code)]

//! ECDSA over NIST P-521 (secp521r1) signature wrappers for the OxiCrypto stack.
//!
//! Keys are provided as raw 66-byte scalars (signing) or SEC1-encoded bytes
//! (compressed 67 bytes or uncompressed 133 bytes) for verifying.

use oxicrypto_core::{CryptoError, Vec};
use p521::ecdsa::{
    signature::{Signer as EcdsaSigner, Verifier as EcdsaVerifier},
    Signature, SigningKey, VerifyingKey,
};

/// ECDSA P-521 signing key.
pub struct EcdsaP521Signer {
    signing_key: SigningKey,
}

impl EcdsaP521Signer {
    /// Construct from 66-byte raw scalar bytes.
    pub fn from_bytes(scalar: &[u8]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_slice(scalar).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { signing_key })
    }

    /// Sign `message` and return DER-encoded signature bytes.
    #[must_use = "signature result must be checked"]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig: Signature = EcdsaSigner::sign(&self.signing_key, message);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// Return the corresponding verifying key as compressed SEC1 bytes (67 bytes).
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }
}

/// ECDSA P-521 verifying key.
pub struct EcdsaP521Verifier {
    verifying_key: VerifyingKey,
}

impl EcdsaP521Verifier {
    /// Construct from SEC1-encoded public key bytes (compressed 67 bytes or uncompressed 133 bytes).
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
