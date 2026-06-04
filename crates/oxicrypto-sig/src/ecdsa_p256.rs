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

use crate::SignatureFormat;

/// ECDSA P-256 signing key.
///
/// Construct via [`EcdsaP256Signer::from_bytes`] using the raw 32-byte scalar.
pub struct EcdsaP256Signer {
    pub(crate) signing_key: SigningKey,
}

impl EcdsaP256Signer {
    /// Construct from 32-byte raw scalar bytes.
    pub fn from_bytes(scalar: &[u8]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_slice(scalar).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { signing_key })
    }

    /// Signs `message` using ECDSA with deterministic nonce generation per RFC 6979.
    ///
    /// Returns DER-encoded signature bytes. The SHA-256 digest is computed
    /// internally by the signing algorithm.
    #[must_use = "signature result must be checked"]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig: Signature = EcdsaSigner::sign(&self.signing_key, message);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// Sign `message` in the given [`SignatureFormat`] encoding.
    ///
    /// Uses deterministic nonce generation per RFC 6979.
    /// - [`SignatureFormat::Der`]: ASN.1 DER-encoded (variable length, 70–72 bytes).
    /// - [`SignatureFormat::Raw`]: Fixed 64-byte `r ‖ s` big-endian.
    #[must_use = "signature result must be checked"]
    pub fn sign_fmt(&self, message: &[u8], fmt: SignatureFormat) -> Result<Vec<u8>, CryptoError> {
        let sig: Signature = EcdsaSigner::sign(&self.signing_key, message);
        match fmt {
            SignatureFormat::Der => Ok(sig.to_der().as_bytes().to_vec()),
            SignatureFormat::Raw => Ok(<[u8]>::to_vec(sig.to_bytes().as_ref())),
        }
    }

    /// Return the corresponding verifying key as compressed SEC1 bytes (33 bytes).
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }
}

/// ECDSA P-256 verifying key.
pub struct EcdsaP256Verifier {
    pub(crate) verifying_key: VerifyingKey,
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

    /// Verify a signature over `message` in the given [`SignatureFormat`] encoding.
    ///
    /// - [`SignatureFormat::Der`]: expects ASN.1 DER-encoded bytes.
    /// - [`SignatureFormat::Raw`]: expects exactly 64 bytes of `r ‖ s` big-endian.
    #[must_use = "verification result must be checked"]
    pub fn verify_fmt(
        &self,
        message: &[u8],
        sig: &[u8],
        fmt: SignatureFormat,
    ) -> Result<(), CryptoError> {
        let signature: Signature = match fmt {
            SignatureFormat::Der => {
                Signature::from_der(sig).map_err(|_| CryptoError::InvalidTag)?
            }
            SignatureFormat::Raw => {
                if sig.len() != 64 {
                    return Err(CryptoError::InvalidTag);
                }
                // Parse r || s (each 32 bytes big-endian) as a P-256 signature.
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&sig[..32]);
                s.copy_from_slice(&sig[32..]);
                Signature::from_scalars(r, s).map_err(|_| CryptoError::InvalidTag)?
            }
        };
        EcdsaVerifier::verify(&self.verifying_key, message, &signature)
            .map_err(|_| CryptoError::InvalidTag)
    }

    /// Verify a pre-computed message hash.
    ///
    /// `hash` must be the raw 32-byte SHA-256 output. Internally converts the hash
    /// into a scalar and performs ECDSA verification via the `ecdsa::hazmat::VerifyPrimitive`
    /// interface. The `signature` must be DER-encoded.
    ///
    /// **Note:** Use of pre-computed hashes should be limited to large-message scenarios
    /// where you have already computed the hash. Prefer [`verify`](Self::verify) for
    /// standard use cases.
    #[must_use = "verification result must be checked"]
    pub fn verify_prehash(&self, hash: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let signature = Signature::from_der(sig).map_err(|_| CryptoError::InvalidTag)?;
        self.verifying_key
            .verify_prehash(hash, &signature)
            .map_err(|_| CryptoError::InvalidTag)
    }

    /// Verify a signature over `message` using a caller-supplied [`Hash`] implementation.
    ///
    /// The `hash` object computes the message digest; the resulting digest bytes are then
    /// passed to the underlying prehash-verifier. This allows callers to substitute any
    /// `oxicrypto-core` compatible hash algorithm (SHA-256, SHA-384, BLAKE3, …) without
    /// hardcoding the digest algorithm inside this crate.
    ///
    /// The `signature` must be DER-encoded.
    ///
    /// [`Hash`]: oxicrypto_core::Hash
    #[must_use = "verification result must be checked"]
    pub fn verify_with_hash(
        &self,
        hash: &dyn oxicrypto_core::Hash,
        message: &[u8],
        sig: &[u8],
    ) -> Result<(), CryptoError> {
        let digest = hash.hash_to_vec(message)?;
        self.verify_prehash(&digest, sig)
    }
}

impl EcdsaP256Signer {
    /// Sign `message` by first hashing it with the supplied [`Hash`] object.
    ///
    /// Computes `digest = hash(message)`, then signs the raw digest bytes using
    /// `PrehashSigner` (deterministic RFC 6979 nonce). Returns DER-encoded ECDSA.
    ///
    /// Callers can substitute any `oxicrypto-core` `Hash` implementation, making the
    /// signing algorithm hash-agnostic at the API level.
    ///
    /// [`Hash`]: oxicrypto_core::Hash
    #[must_use = "signature result must be checked"]
    pub fn sign_with_hash(
        &self,
        hash: &dyn oxicrypto_core::Hash,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let digest = hash.hash_to_vec(message)?;
        let sig: Signature = self
            .signing_key
            .sign_prehash(&digest)
            .map_err(|_| CryptoError::Internal("ECDSA P-256 prehash sign failed"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}
