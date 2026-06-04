//! AEAD implementations backed by `aws-lc-rs`.
//!
//! Supported algorithms:
//! - AES-128-GCM (key: 16 bytes, nonce: 12 bytes, tag: 16 bytes)
//! - AES-256-GCM (key: 32 bytes, nonce: 12 bytes, tag: 16 bytes)
//! - AES-256-GCM-SIV (key: 32 bytes, nonce: 12 bytes, tag: 16 bytes)
//! - ChaCha20-Poly1305 (key: 32 bytes, nonce: 12 bytes, tag: 16 bytes)

use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, AES_256_GCM_SIV,
    CHACHA20_POLY1305,
};
use oxicrypto_core::{Aead, CryptoError};

/// AEAD cipher variant for aws-lc-rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    Aes128Gcm,
    Aes256Gcm,
    Aes256GcmSiv,
    ChaCha20Poly1305,
}

/// An AEAD implementation backed by `aws-lc-rs`.
///
/// Construct via [`AwsLcAead::aes128_gcm`], [`AwsLcAead::aes256_gcm`],
/// [`AwsLcAead::aes256_gcm_siv`], or [`AwsLcAead::chacha20_poly1305`].
#[derive(Debug, Clone, Copy)]
pub struct AwsLcAead {
    algo: Algo,
}

impl AwsLcAead {
    /// AES-128-GCM: key 16 bytes, nonce 12 bytes, tag 16 bytes.
    #[must_use]
    pub fn aes128_gcm() -> Self {
        Self {
            algo: Algo::Aes128Gcm,
        }
    }

    /// AES-256-GCM: key 32 bytes, nonce 12 bytes, tag 16 bytes.
    #[must_use]
    pub fn aes256_gcm() -> Self {
        Self {
            algo: Algo::Aes256Gcm,
        }
    }

    /// AES-256-GCM-SIV: key 32 bytes, nonce 12 bytes, tag 16 bytes.
    ///
    /// Nonce-misuse resistant variant of AES-GCM.
    #[must_use]
    pub fn aes256_gcm_siv() -> Self {
        Self {
            algo: Algo::Aes256GcmSiv,
        }
    }

    /// ChaCha20-Poly1305: key 32 bytes, nonce 12 bytes, tag 16 bytes.
    #[must_use]
    pub fn chacha20_poly1305() -> Self {
        Self {
            algo: Algo::ChaCha20Poly1305,
        }
    }

    /// Construct from an algorithm name string.
    ///
    /// Recognised names: `"AES-128-GCM"`, `"AES-256-GCM"`, `"AES-256-GCM-SIV"`,
    /// `"CHACHA20-POLY1305"`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "AES-128-GCM" => Some(Self::aes128_gcm()),
            "AES-256-GCM" => Some(Self::aes256_gcm()),
            "AES-256-GCM-SIV" => Some(Self::aes256_gcm_siv()),
            "CHACHA20-POLY1305" => Some(Self::chacha20_poly1305()),
            _ => None,
        }
    }

    fn make_less_safe_key(&self, key: &[u8]) -> Result<LessSafeKey, CryptoError> {
        let algo = match self.algo {
            Algo::Aes128Gcm => &AES_128_GCM,
            Algo::Aes256Gcm => &AES_256_GCM,
            Algo::Aes256GcmSiv => &AES_256_GCM_SIV,
            Algo::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        };
        let unbound = UnboundKey::new(algo, key).map_err(|_| CryptoError::InvalidKey)?;
        Ok(LessSafeKey::new(unbound))
    }

    fn make_nonce(nonce: &[u8]) -> Result<Nonce, CryptoError> {
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonce)
    }
}

impl core::fmt::Display for AwsLcAead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl Aead for AwsLcAead {
    fn name(&self) -> &'static str {
        match self.algo {
            Algo::Aes128Gcm => "AES-128-GCM (aws-lc-rs)",
            Algo::Aes256Gcm => "AES-256-GCM (aws-lc-rs)",
            Algo::Aes256GcmSiv => "AES-256-GCM-SIV (aws-lc-rs)",
            Algo::ChaCha20Poly1305 => "ChaCha20-Poly1305 (aws-lc-rs)",
        }
    }

    fn key_len(&self) -> usize {
        match self.algo {
            Algo::Aes128Gcm => 16,
            Algo::Aes256Gcm => 32,
            Algo::Aes256GcmSiv => 32,
            Algo::ChaCha20Poly1305 => 32,
        }
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
        let required = pt
            .len()
            .checked_add(self.tag_len())
            .ok_or(CryptoError::BadInput)?;
        if ct_out.len() < required {
            return Err(CryptoError::BufferTooSmall);
        }

        let less_safe = self.make_less_safe_key(key)?;
        let nonce_val = Self::make_nonce(nonce)?;

        // Copy plaintext into output buffer; seal_in_place_separate_tag encrypts in-place.
        ct_out[..pt.len()].copy_from_slice(pt);

        let tag = less_safe
            .seal_in_place_separate_tag(nonce_val, Aad::from(aad), &mut ct_out[..pt.len()])
            .map_err(|_| CryptoError::Internal("aws-lc-rs AEAD seal failed"))?;

        ct_out[pt.len()..required].copy_from_slice(tag.as_ref());
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
        if ct.len() < self.tag_len() {
            return Err(CryptoError::BadInput);
        }
        let pt_len = ct.len() - self.tag_len();
        if pt_out.len() < pt_len {
            return Err(CryptoError::BufferTooSmall);
        }

        let less_safe = self.make_less_safe_key(key)?;
        let nonce_val = Self::make_nonce(nonce)?;

        let ciphertext = &ct[..pt_len];
        let tag = &ct[pt_len..];

        less_safe
            .open_separate_gather(
                nonce_val,
                Aad::from(aad),
                ciphertext,
                tag,
                &mut pt_out[..pt_len],
            )
            .map_err(|_| CryptoError::InvalidTag)?;

        Ok(pt_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(cipher: AwsLcAead, key: &[u8]) {
        let nonce = vec![0x11u8; 12];
        let aad = b"aws-lc adapter aad";
        let pt = b"hello from aws-lc-rs";

        let mut ct = vec![0u8; pt.len() + cipher.tag_len()];
        let written = cipher.seal(key, &nonce, aad, pt, &mut ct).expect("seal");
        assert_eq!(written, pt.len() + 16);

        let mut recovered = vec![0u8; pt.len()];
        let n = cipher
            .open(key, &nonce, aad, &ct[..written], &mut recovered)
            .expect("open");
        assert_eq!(&recovered[..n], pt.as_ref());
    }

    #[test]
    fn aes128gcm_round_trip() {
        round_trip(AwsLcAead::aes128_gcm(), &[0x42u8; 16]);
    }

    #[test]
    fn aes256gcm_round_trip() {
        round_trip(AwsLcAead::aes256_gcm(), &[0x42u8; 32]);
    }

    #[test]
    fn chacha20poly1305_round_trip() {
        round_trip(AwsLcAead::chacha20_poly1305(), &[0x42u8; 32]);
    }

    #[test]
    fn aes256gcm_siv_round_trip() {
        round_trip(AwsLcAead::aes256_gcm_siv(), &[0x42u8; 32]);
    }

    #[test]
    fn from_name_known() {
        assert!(AwsLcAead::from_name("AES-128-GCM").is_some());
        assert!(AwsLcAead::from_name("AES-256-GCM").is_some());
        assert!(AwsLcAead::from_name("AES-256-GCM-SIV").is_some());
        assert!(AwsLcAead::from_name("CHACHA20-POLY1305").is_some());
        assert!(AwsLcAead::from_name("unknown").is_none());
    }

    #[test]
    fn display_delegates_to_name() {
        let c = AwsLcAead::aes256_gcm();
        assert_eq!(format!("{c}"), c.name());
    }

    #[test]
    fn wrong_tag_fails() {
        let cipher = AwsLcAead::aes256_gcm();
        let key = [0x55u8; 32];
        let nonce = [0x22u8; 12];
        let pt = b"secret data";
        let mut ct = vec![0u8; pt.len() + 16];
        cipher.seal(&key, &nonce, b"", pt, &mut ct).expect("seal");
        // Corrupt a tag byte
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        let mut pt_out = vec![0u8; pt.len()];
        assert_eq!(
            cipher.open(&key, &nonce, b"", &ct, &mut pt_out),
            Err(CryptoError::InvalidTag)
        );
    }
}
