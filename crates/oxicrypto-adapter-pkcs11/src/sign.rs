//! PKCS#11 signing via `C_Sign` / `C_Verify`.

use cryptoki::{mechanism::Mechanism, object::ObjectHandle};
use oxicrypto_core::{CryptoError, Signer, Verifier};

use crate::provider::{Pkcs11Provider, PkcsError};

/// A PKCS#11-backed signer.
///
/// Wraps a live [`Pkcs11Provider`] session (which internally uses a `Mutex`
/// for thread safety).  The signing mechanism and key handle are supplied
/// at call time via [`Pkcs11Signer::sign_with_handle`].
///
/// # Note on the `Signer` trait
///
/// The `oxicrypto_core::Signer` trait takes raw `sk: &[u8]` bytes.  For
/// PKCS#11, private key material never leaves the HSM; the key is addressed
/// by a [`cryptoki::object::ObjectHandle`].  The blanket `Signer` impl here
/// always returns `CryptoError::BadInput` — use `sign_with_handle` directly.
#[derive(Debug)]
pub struct Pkcs11Signer<'a> {
    provider: &'a Pkcs11Provider,
}

impl<'a> Pkcs11Signer<'a> {
    /// Create a new signer using the session in `provider`.
    pub fn new(provider: &'a Pkcs11Provider) -> Self {
        Self { provider }
    }

    /// Perform a single-part sign using a known `ObjectHandle`.
    ///
    /// The `mechanism` (e.g. `Mechanism::EcdsaSha256`) is supplied by the
    /// caller and must match the key type on the token.
    ///
    /// Returns the raw signature bytes as returned by the HSM.
    ///
    /// # Errors
    /// Returns [`PkcsError::Operation`] if the `C_Sign` call fails.
    pub fn sign_with_handle(
        &self,
        mechanism: Mechanism<'_>,
        key: ObjectHandle,
        msg: &[u8],
    ) -> Result<Vec<u8>, PkcsError> {
        self.provider
            .with_session(|session| session.sign(&mechanism, key, msg))
    }
}

impl Signer for Pkcs11Signer<'_> {
    fn name(&self) -> &'static str {
        "PKCS#11 (cryptoki)"
    }

    fn signature_len(&self) -> usize {
        // Conservative upper bound; use sign_with_handle for exact output length.
        512
    }

    fn sign(&self, _sk: &[u8], _msg: &[u8], _sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        // PKCS#11 requires an ObjectHandle; raw sk bytes are not applicable.
        Err(CryptoError::BadInput)
    }
}

/// A PKCS#11-backed verifier.
///
/// The verification mechanism and key object handle are supplied at call time
/// via [`Pkcs11Verifier::verify_with_handle`].
#[derive(Debug)]
pub struct Pkcs11Verifier<'a> {
    provider: &'a Pkcs11Provider,
}

impl<'a> Pkcs11Verifier<'a> {
    /// Create a new verifier using the session in `provider`.
    pub fn new(provider: &'a Pkcs11Provider) -> Self {
        Self { provider }
    }

    /// Perform a single-part verify using a known `ObjectHandle`.
    ///
    /// # Errors
    /// Returns [`PkcsError::Operation`] on `C_Verify` failure.
    pub fn verify_with_handle(
        &self,
        mechanism: Mechanism<'_>,
        key: ObjectHandle,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), PkcsError> {
        self.provider
            .with_session(|session| session.verify(&mechanism, key, msg, sig))
    }
}

impl Verifier for Pkcs11Verifier<'_> {
    fn name(&self) -> &'static str {
        "PKCS#11 (cryptoki)"
    }

    fn verify(&self, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<(), CryptoError> {
        // PKCS#11 requires an ObjectHandle; raw pk bytes are not applicable here.
        Err(CryptoError::BadInput)
    }
}
