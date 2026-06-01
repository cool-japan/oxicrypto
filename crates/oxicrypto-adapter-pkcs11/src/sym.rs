//! PKCS#11 symmetric cipher operations via `C_Encrypt` / `C_Decrypt`.

use cryptoki::{mechanism::Mechanism, object::ObjectHandle};
use oxicrypto_core::CryptoError;

use crate::provider::{Pkcs11Provider, PkcsError};

/// A PKCS#11-backed symmetric encrypt/decrypt adaptor.
///
/// Wraps a [`Pkcs11Provider`] session (which uses an internal `Mutex` for
/// thread safety).  The `Mechanism` (including any IV/GCM parameters) is
/// passed at call time.
///
/// # Design note
/// PKCS#11 requires the IV/nonce to be embedded in the mechanism parameters
/// (e.g. `Mechanism::AesGcm(GcmParams { iv, aad, tag_bits })`) rather than
/// passed as a separate argument.  The caller must construct the appropriate
/// `Mechanism` before calling `encrypt` or `decrypt`.
#[derive(Debug)]
pub struct Pkcs11SymOp<'a> {
    provider: &'a Pkcs11Provider,
}

impl<'a> Pkcs11SymOp<'a> {
    /// Create a new symmetric operation adaptor using `provider`.
    pub fn new(provider: &'a Pkcs11Provider) -> Self {
        Self { provider }
    }

    /// Perform a single-part `C_Encrypt` via the given `mechanism` and `key` handle.
    ///
    /// Returns the raw ciphertext bytes (including any appended tag).
    ///
    /// # Errors
    /// Returns [`PkcsError::Operation`] if the `C_Encrypt` call fails.
    pub fn encrypt(
        &self,
        mechanism: Mechanism<'_>,
        key: ObjectHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PkcsError> {
        self.provider
            .with_session(|session| session.encrypt(&mechanism, key, plaintext))
    }

    /// Perform a single-part `C_Decrypt` via the given `mechanism` and `key` handle.
    ///
    /// Returns the recovered plaintext bytes.
    ///
    /// # Errors
    /// Returns [`PkcsError::Operation`] if the `C_Decrypt` call fails (including
    /// authentication tag mismatch for AEAD modes).
    pub fn decrypt(
        &self,
        mechanism: Mechanism<'_>,
        key: ObjectHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PkcsError> {
        self.provider
            .with_session(|session| session.decrypt(&mechanism, key, ciphertext))
    }

    /// Map a `PkcsError` to `CryptoError` for callers that work with the
    /// generic trait surface.
    pub fn map_err(e: PkcsError) -> CryptoError {
        CryptoError::from(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify PkcsError → CryptoError conversion for the sym op path.
    #[test]
    fn pkcs11_sym_op_error_mapping() {
        let e = PkcsError::Operation("encrypt failed".to_string());
        let ce = Pkcs11SymOp::map_err(e);
        assert!(matches!(ce, CryptoError::Internal(_)));
    }
}
