//! PKCS#11 signing via `C_Sign` / `C_Verify`.

use std::sync::Arc;

use cryptoki::{mechanism::Mechanism, object::ObjectHandle};
use oxicrypto_core::{CryptoError, Signer, Verifier};

use crate::provider::{Pkcs11Provider, PkcsError};

// ---------------------------------------------------------------------------
// SignMechanism — Send + Sync wrapper for signing mechanism selection
// ---------------------------------------------------------------------------

/// A `Send + Sync` representation of the signing mechanism to use.
///
/// `cryptoki::mechanism::Mechanism` is `!Send` because some of its variants
/// contain raw pointers.  This lightweight enum covers only the signing
/// mechanisms and converts to `Mechanism` at call time within a single thread.
#[derive(Debug, Clone, Copy)]
pub enum SignMechanism {
    /// Raw ECDSA (hash performed externally).
    Ecdsa,
    /// ECDSA with SHA-1 pre-hashing.
    EcdsaSha1,
    /// ECDSA with SHA-224 pre-hashing.
    EcdsaSha224,
    /// ECDSA with SHA-256 pre-hashing.
    EcdsaSha256,
    /// ECDSA with SHA-384 pre-hashing.
    EcdsaSha384,
    /// ECDSA with SHA-512 pre-hashing.
    EcdsaSha512,
    /// RSA-PKCS1v1.5 with SHA-256 (CKM_SHA256_RSA_PKCS).
    RsaSha256Pkcs,
    /// RSA-PKCS1v1.5 with SHA-384 (CKM_SHA384_RSA_PKCS).
    RsaSha384Pkcs,
    /// RSA-PKCS1v1.5 with SHA-512 (CKM_SHA512_RSA_PKCS).
    RsaSha512Pkcs,
}

impl SignMechanism {
    /// Convert to the corresponding `cryptoki::mechanism::Mechanism`.
    pub fn to_mechanism(self) -> Mechanism<'static> {
        match self {
            SignMechanism::Ecdsa => Mechanism::Ecdsa,
            SignMechanism::EcdsaSha1 => Mechanism::EcdsaSha1,
            SignMechanism::EcdsaSha224 => Mechanism::EcdsaSha224,
            SignMechanism::EcdsaSha256 => Mechanism::EcdsaSha256,
            SignMechanism::EcdsaSha384 => Mechanism::EcdsaSha384,
            SignMechanism::EcdsaSha512 => Mechanism::EcdsaSha512,
            SignMechanism::RsaSha256Pkcs => Mechanism::Sha256RsaPkcs,
            SignMechanism::RsaSha384Pkcs => Mechanism::Sha384RsaPkcs,
            SignMechanism::RsaSha512Pkcs => Mechanism::Sha512RsaPkcs,
        }
    }
}

// ---------------------------------------------------------------------------
// Pkcs11Signer
// ---------------------------------------------------------------------------

/// A PKCS#11-backed signer.
///
/// Wraps a live [`Pkcs11Provider`] session (which internally uses a `Mutex`
/// for thread safety).  The signing mechanism and key handle are supplied
/// at call time via [`Pkcs11Signer::sign_with_handle`].
///
/// ## Label-based `Signer` trait implementation
///
/// The `oxicrypto_core::Signer` trait accepts raw `sk: &[u8]` bytes.  For
/// PKCS#11, private key material never leaves the HSM; keys are addressed
/// by a [`cryptoki::object::ObjectHandle`].
///
/// When a `Pkcs11Signer` is constructed via [`Pkcs11SignerBuilder`] with a
/// `key_label`, the `Signer::sign` implementation interprets `sk` as a
/// UTF-8 key label and looks up the private key on the token.  This avoids
/// the need to pass an `ObjectHandle` through the generic `Signer` interface.
///
/// Use [`Pkcs11Signer::sign_with_handle`] directly when you already have an
/// `ObjectHandle`.
#[derive(Debug)]
pub struct Pkcs11Signer {
    provider: Arc<Pkcs11Provider>,
    /// Optional pre-configured signing mechanism (set by the builder).
    mechanism: Option<SignMechanism>,
    /// Optional default key label used when `sk` is empty in `Signer::sign`.
    default_key_label: Option<String>,
}

impl Pkcs11Signer {
    /// Create a new signer using the session in `provider`.
    pub fn new(provider: Arc<Pkcs11Provider>) -> Self {
        Self {
            provider,
            mechanism: None,
            default_key_label: None,
        }
    }

    /// Perform a single-part sign using a known `ObjectHandle`.
    ///
    /// The `mechanism` (e.g. `Mechanism::EcdsaSha256`) is supplied by the
    /// caller and must match the key type on the token.
    ///
    /// Returns the raw signature bytes as returned by the HSM.
    ///
    /// # Errors
    /// Returns [`PkcsError::Cryptoki`] if the `C_Sign` call fails.
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

impl Signer for Pkcs11Signer {
    fn name(&self) -> &'static str {
        "PKCS#11 (cryptoki)"
    }

    fn signature_len(&self) -> usize {
        // Conservative upper bound; use sign_with_handle for exact output length.
        512
    }

    /// Sign `msg` using the key addressed by `sk`.
    ///
    /// `sk` is interpreted as a UTF-8 key label.  The private key is looked
    /// up on the token via `C_FindObjects`.  The mechanism is ECDSA (raw)
    /// by default; override via [`Pkcs11SignerBuilder::mechanism`].
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        // Resolve the key label: use `sk` bytes (UTF-8) if non-empty, otherwise
        // fall back to the pre-configured default label from the builder.
        let label: &str = if sk.is_empty() {
            self.default_key_label
                .as_deref()
                .ok_or(CryptoError::InvalidKey)?
        } else {
            core::str::from_utf8(sk).map_err(|_| CryptoError::InvalidKey)?
        };

        let handle = self
            .provider
            .find_private_key(label)
            .map_err(|_| CryptoError::InvalidKey)?;

        // Determine the mechanism to use: stored one (from builder) or ECDSA default.
        let mech_kind = self.mechanism.unwrap_or(SignMechanism::Ecdsa);
        let mechanism = mech_kind.to_mechanism();

        let sig = self
            .provider
            .with_session(|session| session.sign(&mechanism, handle, msg))
            .map_err(|_| CryptoError::Sign)?;

        if sig_out.len() < sig.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        let n = sig.len();
        sig_out[..n].copy_from_slice(&sig);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Pkcs11Verifier
// ---------------------------------------------------------------------------

/// A PKCS#11-backed verifier.
///
/// The verification mechanism and key object handle are supplied at call time
/// via [`Pkcs11Verifier::verify_with_handle`].
#[derive(Debug)]
pub struct Pkcs11Verifier {
    provider: Arc<Pkcs11Provider>,
}

impl Pkcs11Verifier {
    /// Create a new verifier using the session in `provider`.
    pub fn new(provider: Arc<Pkcs11Provider>) -> Self {
        Self { provider }
    }

    /// Perform a single-part verify using a known `ObjectHandle`.
    ///
    /// # Errors
    /// Returns [`PkcsError::Cryptoki`] on `C_Verify` failure.
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

impl Verifier for Pkcs11Verifier {
    fn name(&self) -> &'static str {
        "PKCS#11 (cryptoki)"
    }

    fn verify(&self, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<(), CryptoError> {
        // PKCS#11 requires an ObjectHandle; raw pk bytes are not applicable here.
        Err(CryptoError::BadInput)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`Pkcs11Signer`].
///
/// Allows pre-configuring the signing mechanism and key label so that the
/// `Signer` trait can be used without always passing an `ObjectHandle`.
///
/// # Example
///
/// ```no_run
/// # use std::sync::Arc;
/// # use oxicrypto_adapter_pkcs11::provider::Pkcs11Provider;
/// # use oxicrypto_adapter_pkcs11::sign::{Pkcs11SignerBuilder, SignMechanism};
/// # fn example(provider: Arc<Pkcs11Provider>) {
/// let signer = Pkcs11SignerBuilder::new(provider)
///     .mechanism(SignMechanism::EcdsaSha256)
///     .key_label("my-ecdsa-key")
///     .build();
/// # let _ = signer;
/// # }
/// ```
#[derive(Debug)]
pub struct Pkcs11SignerBuilder {
    provider: Arc<Pkcs11Provider>,
    mechanism: Option<SignMechanism>,
    key_label: Option<String>,
}

impl Pkcs11SignerBuilder {
    /// Start building with the given provider.
    pub fn new(provider: Arc<Pkcs11Provider>) -> Self {
        Self {
            provider,
            mechanism: None,
            key_label: None,
        }
    }

    /// Override the signing mechanism (default: [`SignMechanism::Ecdsa`]).
    pub fn mechanism(mut self, mechanism: SignMechanism) -> Self {
        self.mechanism = Some(mechanism);
        self
    }

    /// Set the CKA_LABEL of the private key to use.
    pub fn key_label(mut self, label: impl Into<String>) -> Self {
        self.key_label = Some(label.into());
        self
    }

    /// Consume the builder and return a [`Pkcs11Signer`].
    pub fn build(self) -> Pkcs11Signer {
        Pkcs11Signer {
            provider: self.provider,
            mechanism: self.mechanism,
            default_key_label: self.key_label,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builder produces a Pkcs11Signer — structural / type-level test.
    ///
    /// Verifies the builder's API compiles and returns the correct type.
    #[test]
    fn test_builder_type_check() {
        fn build_fn(provider: Arc<Pkcs11Provider>) -> Pkcs11Signer {
            Pkcs11SignerBuilder::new(provider)
                .mechanism(SignMechanism::EcdsaSha256)
                .key_label("test-key")
                .build()
        }
        // Do not call `build_fn` — it requires a real provider.
        // This compile-time check is sufficient for the structural test.
        let _ = build_fn as fn(Arc<Pkcs11Provider>) -> Pkcs11Signer;
    }

    /// Verify that `Pkcs11SignerBuilder::new(p).build()` returns `Pkcs11Signer`.
    #[test]
    fn test_builder_produces_signer() {
        fn assert_type(_: Pkcs11Signer) {}
        fn make(p: Arc<Pkcs11Provider>) {
            let signer = Pkcs11SignerBuilder::new(p).build();
            assert_type(signer);
        }
        // `make` is never called; the compile-time type check is sufficient.
        let _ = make as fn(Arc<Pkcs11Provider>);
    }
}
