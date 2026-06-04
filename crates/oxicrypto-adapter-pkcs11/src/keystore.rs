//! `oxistore-encrypt` `KeyProvider` bridge for PKCS#11 HSMs.
//!
//! This module is only compiled when the `oxistore` feature is enabled, which
//! pulls in the `oxistore-encrypt` crate.
//!
//! # Security Model
//!
//! PKCS#11 private/secret keys are typically non-extractable (the raw key
//! material never leaves the HSM).  To supply the 32-byte key required by
//! `oxistore_encrypt::KeyProvider`, this implementation derives a synthetic
//! key by having the HSM sign a fixed deterministic derivation vector using
//! a HMAC-SHA-256 key (labelled `derivation_label`) stored on the token.
//!
//! The derivation is:
//! ```text
//! derived_key = truncate_to_32(C_Sign(hmac_key, b"oxistore-key-derive-v1"))
//! ```
//!
//! This means:
//! - The 32-byte key only exists in RAM for as long as `Pkcs11KeyProvider` is
//!   live — it is zeroized on drop.
//! - If the HSM token or the HMAC key is destroyed, the derived key is
//!   unrecoverable.
//! - The derivation is deterministic: same token + same HMAC key always
//!   yields the same 32 bytes.
//!
//! # Alternative: Extractable Key
//!
//! If the AES key is created with `CKA_EXTRACTABLE=true`, the raw 32 bytes
//! can be read directly from the token via `C_GetAttributeValue`.  The
//! `Pkcs11ExtractableKeyProvider` type implements this simpler path.

use std::sync::Arc;

use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    types::Ulong,
};
use oxistore_encrypt::{EncryptError, KeyProvider};

use crate::provider::{Pkcs11Provider, PkcsError};

// ---------------------------------------------------------------------------
// Derivation constant
// ---------------------------------------------------------------------------

/// Context string used in the HMAC-based key derivation.
const DERIVATION_CONTEXT: &[u8] = b"oxistore-key-derive-v1";

// ---------------------------------------------------------------------------
// Pkcs11KeyProvider — HMAC-based HSM derivation
// ---------------------------------------------------------------------------

/// A `KeyProvider` backed by a HMAC-SHA-256 key stored on a PKCS#11 token.
///
/// The 32-byte key returned by [`KeyProvider::get_key`] is derived at
/// construction time by having the HSM compute
/// `HMAC-SHA-256(hmac_key, "oxistore-key-derive-v1")` and caching the result.
///
/// The cached key bytes are held in a fixed-size array on the heap; they are
/// overwritten with zeros when `Pkcs11KeyProvider` is dropped.
///
/// # Construction
///
/// Use [`Pkcs11KeyProvider::new`].  The `derivation_label` must be the
/// `CKA_LABEL` of a `CKO_SECRET_KEY` / `CKK_GENERIC_SECRET` (HMAC-capable)
/// key on the token.  You can generate such a key with
/// [`Pkcs11Provider::generate_hmac_key`].
///
/// # Thread safety
///
/// `Pkcs11KeyProvider` is `Send + Sync` because the derived key bytes do not
/// change after construction and the `Pkcs11Provider` mutex is only accessed
/// during `new`.
#[derive(Debug)]
pub struct Pkcs11KeyProvider {
    /// Derived key bytes cached in memory (zeroized on drop).
    derived_key: Box<[u8; 32]>,
}

impl Pkcs11KeyProvider {
    /// Derive a 32-byte key using the HMAC-SHA-256 key labelled
    /// `derivation_label` on the PKCS#11 token.
    ///
    /// # Errors
    /// Returns a [`EncryptError::KeyDerivationFailed`] if:
    /// - The key is not found on the token.
    /// - The `C_Sign` (HMAC) operation fails.
    /// - The resulting signature is shorter than 32 bytes (should never
    ///   happen for SHA-256 HMAC).
    pub fn new(
        provider: Arc<Pkcs11Provider>,
        derivation_label: &str,
    ) -> Result<Self, EncryptError> {
        let key_handle = provider
            .find_secret_key(derivation_label)
            .map_err(|e| EncryptError::KeyDerivationFailed(pkcs_err_to_string(e)))?;

        let hmac_sig = provider
            .with_session(|session| {
                session.sign(&Mechanism::Sha256Hmac, key_handle, DERIVATION_CONTEXT)
            })
            .map_err(|e| EncryptError::KeyDerivationFailed(pkcs_err_to_string(e)))?;

        if hmac_sig.len() < 32 {
            return Err(EncryptError::KeyDerivationFailed(format!(
                "HMAC-SHA-256 output too short: {} bytes",
                hmac_sig.len()
            )));
        }

        let mut key = Box::new([0u8; 32]);
        key.copy_from_slice(&hmac_sig[..32]);
        Ok(Self { derived_key: key })
    }
}

impl KeyProvider for Pkcs11KeyProvider {
    fn get_key(&self) -> Result<&[u8], EncryptError> {
        Ok(self.derived_key.as_ref())
    }
}

impl Drop for Pkcs11KeyProvider {
    fn drop(&mut self) {
        // Overwrite the derived key bytes with zeros before deallocation.
        self.derived_key.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Pkcs11ExtractableKeyProvider — direct attribute read for extractable keys
// ---------------------------------------------------------------------------

/// A `KeyProvider` that reads a 32-byte AES key directly from a PKCS#11 token
/// using `C_GetAttributeValue` (`CKA_VALUE`).
///
/// This requires the key to have been created with `CKA_EXTRACTABLE=true`.
/// Use this when you control the token configuration and can afford to mark
/// keys as extractable (e.g. in development or when the HSM's access control
/// provides equivalent protection).
///
/// The raw key bytes are cached on construction and zeroized on drop.
#[derive(Debug)]
pub struct Pkcs11ExtractableKeyProvider {
    /// Raw 32-byte key extracted from the token.
    key_bytes: Box<[u8; 32]>,
}

impl Pkcs11ExtractableKeyProvider {
    /// Extract the 32-byte AES key labelled `key_label` from the token.
    ///
    /// # Errors
    /// Returns `EncryptError::KeyDerivationFailed` if:
    /// - The key is not found.
    /// - `C_GetAttributeValue` fails (e.g. key is non-extractable).
    /// - The extracted `CKA_VALUE` is not exactly 32 bytes.
    pub fn new(provider: Arc<Pkcs11Provider>, key_label: &str) -> Result<Self, EncryptError> {
        let handle = provider
            .find_secret_key(key_label)
            .map_err(|e| EncryptError::KeyDerivationFailed(pkcs_err_to_string(e)))?;

        let raw_key = provider
            .extract_key_value(handle)
            .map_err(|e| EncryptError::KeyDerivationFailed(pkcs_err_to_string(e)))?;

        if raw_key.len() != 32 {
            return Err(EncryptError::InvalidKeyLength { got: raw_key.len() });
        }

        let mut key_bytes = Box::new([0u8; 32]);
        key_bytes.copy_from_slice(&raw_key);
        Ok(Self { key_bytes })
    }
}

impl KeyProvider for Pkcs11ExtractableKeyProvider {
    fn get_key(&self) -> Result<&[u8], EncryptError> {
        Ok(self.key_bytes.as_ref())
    }
}

impl Drop for Pkcs11ExtractableKeyProvider {
    fn drop(&mut self) {
        self.key_bytes.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Provider extension helpers
// ---------------------------------------------------------------------------

/// Extension methods on `Pkcs11Provider` needed for keystore integration.
impl Pkcs11Provider {
    /// Generate a HMAC-SHA-256 capable `CKO_SECRET_KEY` on the token.
    ///
    /// The key is `CKA_TOKEN=true`, `CKA_SENSITIVE=true`,
    /// `CKA_EXTRACTABLE=false`, and labelled with `label`.
    ///
    /// # Errors
    /// Returns `PkcsError::Cryptoki` if `C_GenerateKey` fails.
    pub fn generate_hmac_key(&self, label: &str) -> Result<ObjectHandle, PkcsError> {
        let key_bytes = Ulong::try_from(32usize).map_err(|e| PkcsError::Internal(e.to_string()))?;

        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(key_bytes),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        self.with_session(|session| {
            session.generate_key(&Mechanism::GenericSecretKeyGen, &template)
        })
    }

    /// Generate a 32-byte AES key on the token with `CKA_EXTRACTABLE=true`.
    ///
    /// **Warning:** extractable keys can be exported from the HSM.  Only use
    /// this when the HSM's access-control mechanisms provide equivalent
    /// protection (e.g. a wrapped-export policy).
    ///
    /// # Errors
    /// Returns `PkcsError::Cryptoki` if `C_GenerateKey` fails.
    pub fn generate_extractable_aes_key(&self, label: &str) -> Result<ObjectHandle, PkcsError> {
        let key_bytes = Ulong::try_from(32usize).map_err(|e| PkcsError::Internal(e.to_string()))?;

        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(key_bytes),
            Attribute::Token(true),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        self.with_session(|session| session.generate_key(&Mechanism::AesKeyGen, &template))
    }

    /// Read the raw `CKA_VALUE` attribute from a secret key object.
    ///
    /// This only succeeds if the key was created with `CKA_EXTRACTABLE=true`.
    ///
    /// # Errors
    /// Returns `PkcsError::Cryptoki` if `C_GetAttributeValue` fails.
    pub fn extract_key_value(&self, key_handle: ObjectHandle) -> Result<Vec<u8>, PkcsError> {
        let attrs = self
            .with_session(|session| session.get_attributes(key_handle, &[AttributeType::Value]))?;

        for attr in attrs {
            if let Attribute::Value(v) = attr {
                return Ok(v);
            }
        }

        Err(PkcsError::Internal(
            "CKA_VALUE not returned by C_GetAttributeValue".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn pkcs_err_to_string(e: PkcsError) -> String {
    e.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that Pkcs11KeyProvider is Send + Sync.
    #[test]
    fn pkcs11_key_provider_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pkcs11KeyProvider>();
        assert_send_sync::<Pkcs11ExtractableKeyProvider>();
    }

    /// Verify the derivation context constant is stable and non-empty.
    #[test]
    fn derivation_context_is_stable() {
        assert_eq!(DERIVATION_CONTEXT, b"oxistore-key-derive-v1");
        assert!(!DERIVATION_CONTEXT.is_empty());
    }
}
