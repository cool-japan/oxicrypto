//! Pure PKCS#11 HSM key-generation/extraction primitives; carries no
//! higher-layer (store/encryption) knowledge.

use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    types::Ulong,
};

use crate::provider::{Pkcs11Provider, PkcsError};

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
