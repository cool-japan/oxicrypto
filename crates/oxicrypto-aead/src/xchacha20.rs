#![forbid(unsafe_code)]

//! XChaCha20-Poly1305 authenticated encryption for the OxiCrypto stack.
//!
//! XChaCha20-Poly1305 extends the ChaCha20-Poly1305 nonce to 192 bits (24 bytes),
//! making random nonce generation safe even for high-volume encryption.
//!
//! Backed by `chacha20poly1305::XChaCha20Poly1305` (same crate as M1, `aead 0.5` chain).
//!
//! Key: 32 bytes. Nonce: 24 bytes. Tag: 16 bytes.

use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305 as Inner;
use oxicrypto_core::{Aead, CryptoError};

/// XChaCha20-Poly1305 authenticated encryption with a 24-byte nonce.
///
/// Key: 32 bytes, nonce: 24 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct XChaCha20Poly1305;

impl Aead for XChaCha20Poly1305 {
    fn name(&self) -> &'static str {
        "XChaCha20-Poly1305"
    }
    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        24
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
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != 24 {
            return Err(CryptoError::InvalidNonce);
        }
        let required = pt.len().checked_add(16).ok_or(CryptoError::BadInput)?;
        if ct_out.len() < required {
            return Err(CryptoError::BufferTooSmall);
        }
        ct_out[..pt.len()].copy_from_slice(pt);
        let cipher = Inner::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
        let tag = cipher
            .encrypt_in_place_detached(nonce_arr, aad, &mut ct_out[..pt.len()])
            .map_err(|_| CryptoError::Internal("XChaCha20Poly1305 encrypt failed"))?;
        ct_out[pt.len()..required].copy_from_slice(&tag);
        Ok(required)
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != 24 {
            return Err(CryptoError::InvalidNonce);
        }
        if ct.len() < 16 {
            return Err(CryptoError::BadInput);
        }
        let pt_len = ct.len() - 16;
        if pt_out.len() < pt_len {
            return Err(CryptoError::BufferTooSmall);
        }
        pt_out[..pt_len].copy_from_slice(&ct[..pt_len]);
        let cipher = Inner::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
        let tag = aead::Tag::<Inner>::clone_from_slice(&ct[pt_len..]);
        cipher
            .decrypt_in_place_detached(nonce_arr, aad, &mut pt_out[..pt_len], &tag)
            .map_err(|_| CryptoError::InvalidTag)?;
        Ok(pt_len)
    }
}

impl XChaCha20Poly1305 {
    /// Encrypt `pt` with associated data `aad`.
    ///
    /// `ct_out` must be at least `pt.len() + 16` bytes.
    /// Returns the number of bytes written (= `pt.len() + 16`).
    pub fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        const TAG_LEN: usize = 16;
        let required = pt.len().checked_add(TAG_LEN).ok_or(CryptoError::BadInput)?;
        if ct_out.len() < required {
            return Err(CryptoError::BufferTooSmall);
        }
        ct_out[..pt.len()].copy_from_slice(pt);
        let cipher = Inner::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce.as_ref());
        let tag = cipher
            .encrypt_in_place_detached(nonce_arr, aad, &mut ct_out[..pt.len()])
            .map_err(|_| CryptoError::Internal("XChaCha20Poly1305 encrypt failed"))?;
        ct_out[pt.len()..required].copy_from_slice(&tag);
        Ok(required)
    }

    /// Decrypt `ct` (ciphertext ‖ tag) into `pt_out`.
    ///
    /// Returns the number of plaintext bytes written.
    pub fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        const TAG_LEN: usize = 16;
        if ct.len() < TAG_LEN {
            return Err(CryptoError::BadInput);
        }
        let pt_len = ct.len() - TAG_LEN;
        if pt_out.len() < pt_len {
            return Err(CryptoError::BufferTooSmall);
        }
        pt_out[..pt_len].copy_from_slice(&ct[..pt_len]);
        let cipher = Inner::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce.as_ref());
        let tag = aead::Tag::<Inner>::clone_from_slice(&ct[pt_len..]);
        cipher
            .decrypt_in_place_detached(nonce_arr, aad, &mut pt_out[..pt_len], &tag)
            .map_err(|_| CryptoError::InvalidTag)?;
        Ok(pt_len)
    }

    /// Ciphertext overhead (tag length).
    pub const TAG_LEN: usize = 16;
}
