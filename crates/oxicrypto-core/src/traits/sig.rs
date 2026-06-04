use alloc::vec::Vec;

use crate::{CryptoError, KeyPair, SecretVec};

/// Asymmetric signing operation.
///
/// When the `debug` Cargo feature is enabled this trait gains `Debug` as a
/// supertrait, enabling `Box<dyn Signer>` to be formatted with `{:?}`.
pub trait Signer: Send + Sync + crate::traits::MaybeDebug {
    /// Human-readable algorithm identifier (e.g. `"Ed25519"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Fixed signature length in bytes.
    #[must_use]
    fn signature_len(&self) -> usize;
    /// Sign `msg` with `sk` (raw secret-key bytes) and write the signature
    /// into `sig_out`.
    ///
    /// Returns the number of bytes written.
    #[must_use = "result must be checked"]
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError>;
}

/// Asymmetric signature verification.
///
/// When the `debug` Cargo feature is enabled this trait gains `Debug` as a
/// supertrait, enabling `Box<dyn Verifier>` to be formatted with `{:?}`.
pub trait Verifier: Send + Sync + crate::traits::MaybeDebug {
    /// Human-readable algorithm identifier (e.g. `"Ed25519"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Verify `sig` over `msg` with `pk` (raw public-key bytes).
    ///
    /// Returns [`CryptoError::InvalidTag`] on verification failure.
    #[must_use = "result must be checked"]
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError>;
}

/// Key pair generator for asymmetric algorithms.
///
/// When the `debug` Cargo feature is enabled this trait gains `Debug` as a
/// supertrait, enabling `Box<dyn KeyGenerator>` to be formatted with `{:?}`.
pub trait KeyGenerator: Send + Sync + crate::traits::MaybeDebug {
    /// Human-readable algorithm identifier (e.g. `"Ed25519"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Generate a fresh key pair.
    ///
    /// Returns `(secret_key, public_key)` wrapped in [`KeyPair`].
    /// The secret half uses [`SecretVec`] (auto-zeroized on drop).
    #[must_use = "result must be checked"]
    fn generate_keypair(&self) -> Result<KeyPair<SecretVec, Vec<u8>>, CryptoError>;
}
