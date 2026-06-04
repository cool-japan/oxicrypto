//! AES-256-GCM with synthetic IV (deterministic AEAD).
//!
//! # Construction
//!
//! Key-split via HKDF-SHA-256:
//!
//! ```text
//! prk   = HKDF-Extract(salt=[], ikm=key)
//! K_enc = HKDF-Expand(prk, "gcm-synthetic/enc", 32)
//! K_mac = HKDF-Expand(prk, "gcm-synthetic/mac", 32)
//! ```
//!
//! Nonce derivation:
//!
//! ```text
//! nonce12 = HMAC-SHA-256(K_mac, aad || pt)[..12]
//! ```
//!
//! Seal output: `nonce(12) || ciphertext || tag(16)` — 28 bytes overhead total.
//!
//! # Security warning
//!
//! This construction is **weaker than RFC 8452 AES-GCM-SIV**.  Use
//! [`crate::AesGcmSiv256`] for stronger nonce-misuse resistance.  This type is
//! provided for environments where standard AES-GCM is required but nonce
//! management is impractical.
//!
//! The nonce-verification step in `open` provides a **key-committing** property:
//! a ciphertext sealed under one key cannot be opened under a different key
//! without detection.

use digest::KeyInit;
use hmac::{Hmac, Mac as HmacMac};
use oxicrypto_core::{ct_eq, Aead, CryptoError};
use oxicrypto_kdf::{hkdf_sha256_expand, hkdf_sha256_extract};
use sha2::Sha256;

use crate::Aes256Gcm;

type HmacSha256 = Hmac<Sha256>;

// HKDF info strings for key split.
const INFO_ENC: &[u8] = b"gcm-synthetic/enc";
const INFO_MAC: &[u8] = b"gcm-synthetic/mac";

/// AES-256-GCM with a synthetic IV (deterministic AEAD).
///
/// The nonce is derived internally from the key, AAD, and plaintext, so callers
/// **must** pass `nonce = &[]` to [`Aead::seal`] and [`Aead::open`].  Passing a
/// non-empty nonce returns [`CryptoError::InvalidNonce`].
///
/// Wire format: `nonce(12) || ciphertext || gcm_tag(16)`.
/// Total overhead: 28 bytes (`tag_len` returns 28).
///
/// # Security warning
///
/// This construction is weaker than RFC 8452 AES-GCM-SIV.  Use
/// [`crate::AesGcmSiv256`] for stronger nonce-misuse resistance.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyntheticIvAes256Gcm;

/// Combined overhead = 12-byte prepended nonce + 16-byte GCM tag.
const OVERHEAD: usize = 12 + 16;

impl SyntheticIvAes256Gcm {
    /// Derive `K_enc` and `K_mac` from the master key.
    fn derive_subkeys(key: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let prk = hkdf_sha256_extract(&[], key);

        let mut k_enc = [0u8; 32];
        hkdf_sha256_expand(&prk, INFO_ENC, &mut k_enc)?;

        let mut k_mac = [0u8; 32];
        hkdf_sha256_expand(&prk, INFO_MAC, &mut k_mac)?;

        Ok((k_enc, k_mac))
    }

    /// Compute HMAC-SHA-256(k_mac, aad || pt) and return the first 12 bytes as
    /// the synthetic nonce.
    fn derive_nonce(k_mac: &[u8; 32], aad: &[u8], pt: &[u8]) -> Result<[u8; 12], CryptoError> {
        let mut mac = HmacSha256::new_from_slice(k_mac).map_err(|_| CryptoError::InvalidKey)?;
        mac.update(aad);
        mac.update(pt);
        let result = mac.finalize().into_bytes();
        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&result[..12]);
        Ok(nonce12)
    }
}

impl Aead for SyntheticIvAes256Gcm {
    fn name(&self) -> &'static str {
        "AES-256-GCM-SIV-Synthetic"
    }

    /// The master key must be 32 bytes.
    fn key_len(&self) -> usize {
        32
    }

    /// The nonce is derived internally.  Callers must pass `&[]`.
    fn nonce_len(&self) -> usize {
        0
    }

    /// Wire overhead: 12-byte prepended nonce + 16-byte GCM tag.
    fn tag_len(&self) -> usize {
        OVERHEAD
    }

    /// Encrypt `pt` and write `nonce(12) || ciphertext || gcm_tag(16)` into `ct_out`.
    ///
    /// `nonce` **must** be `&[]` — the nonce is derived from the message.
    ///
    /// Returns the number of bytes written (`pt.len() + 28`).
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
        if !nonce.is_empty() {
            return Err(CryptoError::InvalidNonce);
        }

        let required = pt
            .len()
            .checked_add(OVERHEAD)
            .ok_or(CryptoError::BadInput)?;
        if ct_out.len() < required {
            return Err(CryptoError::BufferTooSmall);
        }

        let (k_enc, k_mac) = Self::derive_subkeys(key)?;
        let nonce12 = Self::derive_nonce(&k_mac, aad, pt)?;

        // Write nonce prefix.
        ct_out[..12].copy_from_slice(&nonce12);

        // Encrypt the plaintext portion (ct_out[12..12+pt.len()]) using AES-256-GCM,
        // then append the 16-byte tag.
        let gcm = Aes256Gcm;
        let written = gcm.seal(&k_enc, &nonce12, aad, pt, &mut ct_out[12..required])?;

        // `written` should be pt.len() + 16.
        let total = 12usize.checked_add(written).ok_or(CryptoError::BadInput)?;
        Ok(total)
    }

    /// Decrypt and authenticate a ciphertext produced by [`Self::seal`].
    ///
    /// `ct` must contain `nonce(12) || ciphertext || gcm_tag(16)`.
    /// `nonce` **must** be `&[]`.
    ///
    /// After successful GCM open the nonce is re-derived from the decrypted
    /// plaintext and compared in constant time — this provides key-commitment.
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
        if !nonce.is_empty() {
            return Err(CryptoError::InvalidNonce);
        }

        // Minimum: 12-byte nonce + 16-byte tag (empty ciphertext is valid).
        if ct.len() < OVERHEAD {
            return Err(CryptoError::BadInput);
        }

        let nonce12_stored: [u8; 12] = ct[..12].try_into().map_err(|_| CryptoError::BadInput)?;
        let inner_ct = &ct[12..];
        let pt_len = inner_ct
            .len()
            .checked_sub(16)
            .ok_or(CryptoError::BadInput)?;

        if pt_out.len() < pt_len {
            return Err(CryptoError::BufferTooSmall);
        }

        let (k_enc, k_mac) = Self::derive_subkeys(key)?;

        // Open with AES-256-GCM using the stored nonce.
        let gcm = Aes256Gcm;
        gcm.open(
            &k_enc,
            &nonce12_stored,
            aad,
            inner_ct,
            &mut pt_out[..pt_len],
        )?;

        // Re-derive the nonce from the decrypted plaintext and verify in constant
        // time — this is the key-committing check.
        let nonce12_computed = Self::derive_nonce(&k_mac, aad, &pt_out[..pt_len])?;
        if !ct_eq(&nonce12_computed, &nonce12_stored) {
            // Zeroize the plaintext we just wrote so we don't leak partial output.
            pt_out[..pt_len].fill(0);
            return Err(CryptoError::InvalidTag);
        }

        Ok(pt_len)
    }

    /// Encrypt `buf` in place.
    ///
    /// `nonce` **must** be `&[]` — the nonce is derived from the message.
    ///
    /// On entry `buf` contains the plaintext.  On exit `buf` contains
    /// `nonce(12) || ciphertext || gcm_tag(16)`.
    fn seal_in_place(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        buf: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if !nonce.is_empty() {
            return Err(CryptoError::InvalidNonce);
        }

        let pt_len = buf.len();
        let ct_len = pt_len.checked_add(OVERHEAD).ok_or(CryptoError::BadInput)?;

        // Capture plaintext before modifying buf.
        let pt = buf.clone();

        buf.resize(ct_len, 0u8);
        self.seal(key, nonce, aad, &pt, buf)?;
        Ok(())
    }
}
