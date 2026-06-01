#![forbid(unsafe_code)]

//! AES-GCM-SIV authenticated encryption for the OxiCrypto stack.
//!
//! AES-GCM-SIV (RFC 8452) is a misuse-resistant AEAD: nonce reuse does not
//! expose the plaintext (only reveals that the same message was encrypted twice).
//! It uses the `aes-gcm-siv 0.11` crate aligned with `aead 0.5`.
//!
//! Key: 16 bytes (128-bit) or 32 bytes (256-bit).
//! Nonce: 12 bytes.
//! Tag: 16 bytes.

use aead::{AeadInPlace, KeyInit};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
use oxicrypto_core::{Aead, CryptoError};

fn seal_siv<C: AeadInPlace + KeyInit>(
    key: &[u8],
    key_len: usize,
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct_out: &mut [u8],
) -> Result<usize, CryptoError> {
    const TAG_LEN: usize = 16;
    const NONCE_LEN: usize = 12;
    if key.len() != key_len {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonce);
    }
    let required = pt.len().checked_add(TAG_LEN).ok_or(CryptoError::BadInput)?;
    if ct_out.len() < required {
        return Err(CryptoError::BufferTooSmall);
    }
    ct_out[..pt.len()].copy_from_slice(pt);
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
    let tag = cipher
        .encrypt_in_place_detached(nonce_arr, aad, &mut ct_out[..pt.len()])
        .map_err(|_| CryptoError::Internal("AES-GCM-SIV encrypt failed"))?;
    ct_out[pt.len()..required].copy_from_slice(&tag);
    Ok(required)
}

fn open_siv<C: AeadInPlace + KeyInit>(
    key: &[u8],
    key_len: usize,
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt_out: &mut [u8],
) -> Result<usize, CryptoError> {
    const TAG_LEN: usize = 16;
    const NONCE_LEN: usize = 12;
    if key.len() != key_len {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonce);
    }
    if ct.len() < TAG_LEN {
        return Err(CryptoError::BadInput);
    }
    let pt_len = ct.len() - TAG_LEN;
    if pt_out.len() < pt_len {
        return Err(CryptoError::BufferTooSmall);
    }
    pt_out[..pt_len].copy_from_slice(&ct[..pt_len]);
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
    let tag = aead::Tag::<C>::clone_from_slice(&ct[pt_len..]);
    cipher
        .decrypt_in_place_detached(nonce_arr, aad, &mut pt_out[..pt_len], &tag)
        .map_err(|_| CryptoError::InvalidTag)?;
    Ok(pt_len)
}

// ── AES-128-GCM-SIV ───────────────────────────────────────────────────────

/// AES-128-GCM-SIV authenticated encryption (misuse-resistant).
///
/// Key: 16 bytes, nonce: 12 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct AesGcmSiv128;

impl Aead for AesGcmSiv128 {
    fn name(&self) -> &'static str {
        "AES-128-GCM-SIV"
    }
    fn key_len(&self) -> usize {
        16
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        seal_siv::<Aes128GcmSiv>(key, 16, nonce, aad, pt, ct_out)
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        open_siv::<Aes128GcmSiv>(key, 16, nonce, aad, ct, pt_out)
    }
}

impl AesGcmSiv128 {
    /// Encrypt `pt` with associated data `aad`; output is `ct_out` = ciphertext ‖ tag.
    pub fn seal(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        seal_siv::<Aes128GcmSiv>(key, 16, nonce, aad, pt, ct_out)
    }

    /// Decrypt `ct` (ciphertext ‖ tag) into `pt_out`.
    pub fn open(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        open_siv::<Aes128GcmSiv>(key, 16, nonce, aad, ct, pt_out)
    }

    /// Ciphertext overhead (tag length).
    pub const TAG_LEN: usize = 16;
}

// ── AES-256-GCM-SIV ───────────────────────────────────────────────────────

/// AES-256-GCM-SIV authenticated encryption (misuse-resistant).
///
/// Key: 32 bytes, nonce: 12 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct AesGcmSiv256;

impl Aead for AesGcmSiv256 {
    fn name(&self) -> &'static str {
        "AES-256-GCM-SIV"
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
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        seal_siv::<Aes256GcmSiv>(key, 32, nonce, aad, pt, ct_out)
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        open_siv::<Aes256GcmSiv>(key, 32, nonce, aad, ct, pt_out)
    }
}

impl AesGcmSiv256 {
    /// Encrypt `pt` with associated data `aad`; output is `ct_out` = ciphertext ‖ tag.
    pub fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        seal_siv::<Aes256GcmSiv>(key, 32, nonce, aad, pt, ct_out)
    }

    /// Decrypt `ct` (ciphertext ‖ tag) into `pt_out`.
    pub fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        open_siv::<Aes256GcmSiv>(key, 32, nonce, aad, ct, pt_out)
    }

    /// Ciphertext overhead (tag length).
    pub const TAG_LEN: usize = 16;
}
