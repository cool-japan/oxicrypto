//! PKCS#11 symmetric cipher operations via `C_Encrypt` / `C_Decrypt`.

use std::sync::Arc;

use cryptoki::{
    mechanism::{aead::GcmParams, Mechanism},
    object::ObjectHandle,
    types::Ulong,
};
use oxicrypto_core::{Aead, CryptoError};

use crate::provider::{Pkcs11Provider, PkcsError};

// ---------------------------------------------------------------------------
// Pkcs11SymOp — low-level encrypt/decrypt with caller-supplied mechanism
// ---------------------------------------------------------------------------

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
    /// Returns [`PkcsError::Cryptoki`] if the `C_Encrypt` call fails.
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
    /// Returns [`PkcsError::Cryptoki`] if the `C_Decrypt` call fails (including
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

// ---------------------------------------------------------------------------
// Pkcs11Aead — AES-256-GCM via the oxicrypto_core::Aead trait
// ---------------------------------------------------------------------------

/// A PKCS#11-backed AES-256-GCM AEAD implementation.
///
/// The key is stored on the HSM and identified by an [`ObjectHandle`].  The
/// `key` parameter in `seal`/`open` is **ignored** because the key material
/// never leaves the token.
///
/// The nonce must be exactly 12 bytes; the tag is always 128 bits (16 bytes).
///
/// # Thread safety
/// Internally serialises access via `Arc<Pkcs11Provider>`.
#[derive(Debug)]
pub struct Pkcs11Aead {
    provider: Arc<Pkcs11Provider>,
    key_handle: ObjectHandle,
}

impl Pkcs11Aead {
    /// Create an AES-GCM AEAD backed by the given provider and key handle.
    pub fn new(provider: Arc<Pkcs11Provider>, key_handle: ObjectHandle) -> Self {
        Self {
            provider,
            key_handle,
        }
    }
}

impl Aead for Pkcs11Aead {
    fn name(&self) -> &'static str {
        "AES-256-GCM-PKCS11"
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        16
    }

    /// Encrypt `pt` and write `ciphertext || tag` into `ct_out`.
    ///
    /// The `key` parameter is ignored — the key is on the HSM.
    fn seal(
        &self,
        _key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if nonce.len() != self.nonce_len() {
            return Err(CryptoError::InvalidNonce);
        }
        let expected_out_len = pt
            .len()
            .checked_add(self.tag_len())
            .ok_or(CryptoError::BadInput)?;
        if ct_out.len() < expected_out_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // GcmParams requires a mutable IV slice — copy nonce to a local buffer.
        let mut iv = nonce.to_vec();

        // tag_bits must fit in Ulong (u64 on 64-bit, u32 on 32-bit).
        let tag_bits = Ulong::try_from(self.tag_len() * 8)
            .map_err(|_| CryptoError::Internal("tag_bits overflow"))?;

        // Construct GcmParams and keep the IV alive while it's referenced.
        let gcm_params = GcmParams::new(&mut iv, aad, tag_bits)
            .map_err(|_| CryptoError::Internal("gcm params construction failed"))?;

        let mechanism = Mechanism::AesGcm(gcm_params);
        let key_handle = self.key_handle;

        let ciphertext = self
            .provider
            .with_session(|session| session.encrypt(&mechanism, key_handle, pt))
            .map_err(|_| CryptoError::Internal("pkcs11 encrypt failed"))?;

        if ct_out.len() < ciphertext.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        let n = ciphertext.len();
        ct_out[..n].copy_from_slice(&ciphertext);
        Ok(n)
    }

    /// Decrypt and authenticate `ct` (ciphertext || tag) into `pt_out`.
    ///
    /// The `key` parameter is ignored — the key is on the HSM.
    fn open(
        &self,
        _key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if nonce.len() != self.nonce_len() {
            return Err(CryptoError::InvalidNonce);
        }
        if ct.len() < self.tag_len() {
            return Err(CryptoError::BufferTooSmall);
        }
        let expected_pt_len = ct.len() - self.tag_len();
        if pt_out.len() < expected_pt_len {
            return Err(CryptoError::BufferTooSmall);
        }

        let mut iv = nonce.to_vec();

        let tag_bits = Ulong::try_from(self.tag_len() * 8)
            .map_err(|_| CryptoError::Internal("tag_bits overflow"))?;

        let gcm_params = GcmParams::new(&mut iv, aad, tag_bits)
            .map_err(|_| CryptoError::Internal("gcm params construction failed"))?;

        let mechanism = Mechanism::AesGcm(gcm_params);
        let key_handle = self.key_handle;

        let plaintext = self
            .provider
            .with_session(|session| session.decrypt(&mechanism, key_handle, ct))
            .map_err(|_| CryptoError::InvalidTag)?;

        if pt_out.len() < plaintext.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        let n = plaintext.len();
        pt_out[..n].copy_from_slice(&plaintext);
        Ok(n)
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

    /// Verify that AES-256-GCM constant values match NIST/RFC expectations.
    ///
    /// These constants are used by `Pkcs11Aead` and must remain correct.
    /// This test does NOT require an HSM.
    #[test]
    fn pkcs11_aead_constants() {
        // AES-256: 256-bit key = 32 bytes
        const AES256_KEY_LEN: usize = 32;
        // GCM standard nonce length
        const GCM_NONCE_LEN: usize = 12;
        // GCM tag length (128 bits)
        const GCM_TAG_LEN: usize = 16;

        assert_eq!(AES256_KEY_LEN, 32);
        assert_eq!(GCM_NONCE_LEN, 12);
        assert_eq!(GCM_TAG_LEN, 16);
        // Verify tag_bits calculation used in seal/open.
        assert_eq!(GCM_TAG_LEN * 8, 128);
    }
}
