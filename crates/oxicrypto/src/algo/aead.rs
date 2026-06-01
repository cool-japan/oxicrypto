//! AEAD algorithm selector enum + factory function.

use crate::CryptoError;

/// AEAD algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadAlgo {
    /// AES-128-GCM (key: 16 bytes, nonce: 12 bytes, tag: 16 bytes).
    Aes128Gcm,
    /// AES-256-GCM (key: 32 bytes, nonce: 12 bytes, tag: 16 bytes).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (key: 32 bytes, nonce: 12 bytes, tag: 16 bytes).
    ChaCha20Poly1305,
    /// AES-128-GCM-SIV (key: 16 bytes, nonce: 12 bytes, tag: 16 bytes).
    /// Misuse-resistant: nonce reuse does not expose plaintext.
    Aes128GcmSiv,
    /// AES-256-GCM-SIV (key: 32 bytes, nonce: 12 bytes, tag: 16 bytes).
    Aes256GcmSiv,
    /// XChaCha20-Poly1305 (key: 32 bytes, nonce: 24 bytes, tag: 16 bytes).
    /// Extended nonce variant safe for random nonce generation.
    XChaCha20Poly1305,
    /// AES-128-CCM (key: 16 bytes, nonce: 13 bytes, tag: 16 bytes).
    Aes128Ccm,
    /// AES-256-CCM (key: 32 bytes, nonce: 13 bytes, tag: 16 bytes).
    Aes256Ccm,
    /// AES-128-OCB3 (key: 16 bytes, nonce: 12 bytes, tag: 16 bytes).
    Aes128Ocb3,
    /// AES-256-OCB3 (key: 32 bytes, nonce: 12 bytes, tag: 16 bytes).
    Aes256Ocb3,
    /// Deoxys-II-128-128 (key: 16 bytes, nonce: 16 bytes, tag: 16 bytes).
    /// Nonce-misuse-resistant AEAD (SCT-2 mode) built on the Deoxys-BC tweakable
    /// block cipher; CAESAR final-portfolio winner for the defence-in-depth use case.
    DeoxysII128,
}

/// Return a boxed [`oxicrypto_core::Aead`] implementation for `algo`.
#[cfg(feature = "pure")]
#[must_use]
pub fn aead_impl(algo: AeadAlgo) -> oxicrypto_core::Box<dyn oxicrypto_core::Aead + Send + Sync> {
    match algo {
        AeadAlgo::Aes128Gcm => oxicrypto_core::Box::new(oxicrypto_aead::Aes128Gcm),
        AeadAlgo::Aes256Gcm => oxicrypto_core::Box::new(oxicrypto_aead::Aes256Gcm),
        AeadAlgo::ChaCha20Poly1305 => oxicrypto_core::Box::new(oxicrypto_aead::ChaCha20Poly1305),
        AeadAlgo::Aes128GcmSiv => oxicrypto_core::Box::new(oxicrypto_aead::AesGcmSiv128),
        AeadAlgo::Aes256GcmSiv => oxicrypto_core::Box::new(oxicrypto_aead::AesGcmSiv256),
        AeadAlgo::XChaCha20Poly1305 => oxicrypto_core::Box::new(oxicrypto_aead::XChaCha20Poly1305),
        AeadAlgo::Aes128Ccm => oxicrypto_core::Box::new(oxicrypto_aead::Aes128Ccm),
        AeadAlgo::Aes256Ccm => oxicrypto_core::Box::new(oxicrypto_aead::Aes256Ccm),
        AeadAlgo::Aes128Ocb3 => oxicrypto_core::Box::new(oxicrypto_aead::Aes128Ocb3),
        AeadAlgo::Aes256Ocb3 => oxicrypto_core::Box::new(oxicrypto_aead::Aes256Ocb3),
        AeadAlgo::DeoxysII128 => oxicrypto_core::Box::new(oxicrypto_aead::Deoxys2_128),
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl core::fmt::Display for AeadAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            AeadAlgo::Aes128Gcm => "AES-128-GCM",
            AeadAlgo::Aes256Gcm => "AES-256-GCM",
            AeadAlgo::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            AeadAlgo::Aes128GcmSiv => "AES-128-GCM-SIV",
            AeadAlgo::Aes256GcmSiv => "AES-256-GCM-SIV",
            AeadAlgo::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            AeadAlgo::Aes128Ccm => "AES-128-CCM",
            AeadAlgo::Aes256Ccm => "AES-256-CCM",
            AeadAlgo::Aes128Ocb3 => "AES-128-OCB3",
            AeadAlgo::Aes256Ocb3 => "AES-256-OCB3",
            AeadAlgo::DeoxysII128 => "Deoxys-II-128-128",
        })
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

impl core::str::FromStr for AeadAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AES-128-GCM" | "aes-128-gcm" | "AES128GCM" => Ok(AeadAlgo::Aes128Gcm),
            "AES-256-GCM" | "aes-256-gcm" | "AES256GCM" => Ok(AeadAlgo::Aes256Gcm),
            "ChaCha20-Poly1305" | "chacha20-poly1305" | "CHACHA20POLY1305" => {
                Ok(AeadAlgo::ChaCha20Poly1305)
            }
            "AES-128-GCM-SIV" | "aes-128-gcm-siv" => Ok(AeadAlgo::Aes128GcmSiv),
            "AES-256-GCM-SIV" | "aes-256-gcm-siv" => Ok(AeadAlgo::Aes256GcmSiv),
            "XChaCha20-Poly1305" | "xchacha20-poly1305" | "XCHACHA20POLY1305" => {
                Ok(AeadAlgo::XChaCha20Poly1305)
            }
            "AES-128-CCM" | "aes-128-ccm" | "AES128CCM" => Ok(AeadAlgo::Aes128Ccm),
            "AES-256-CCM" | "aes-256-ccm" | "AES256CCM" => Ok(AeadAlgo::Aes256Ccm),
            "AES-128-OCB3" | "aes-128-ocb3" | "AES128OCB3" => Ok(AeadAlgo::Aes128Ocb3),
            "AES-256-OCB3" | "aes-256-ocb3" | "AES256OCB3" => Ok(AeadAlgo::Aes256Ocb3),
            "Deoxys-II-128-128" | "deoxys-ii-128-128" | "DEOXYSII128" => Ok(AeadAlgo::DeoxysII128),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ── TryFrom<&str> ─────────────────────────────────────────────────────────────

impl TryFrom<&str> for AeadAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
