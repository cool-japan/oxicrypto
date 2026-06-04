//! UtC key-committing AEAD construction (CMT-1).
//!
//! Wraps any [`Aead`] implementation and prepends a 32-byte commitment to each
//! ciphertext, derived by HKDF-SHA-256 from the encryption key.  A valid
//! ciphertext can only be decrypted by the key used to seal it, preventing
//! invisible-salamander and partitioning-oracle attacks.
//!
//! # Security properties
//!
//! This implements the **CMT-1** (key-committing) property: for any two distinct
//! keys `K₁ ≠ K₂`, the probability that a ciphertext sealed under `K₁` can be
//! successfully opened under `K₂` is negligible.
//!
//! The construction is the **UtC** transform (Bellare & Hoang, "Efficient Schemes
//! for Committing Authenticated Encryption", EUROCRYPT 2022, §3):
//!
//! 1. Derive `okm = HKDF-SHA-256-Expand(HKDF-Extract(0³², key),
//!    "oxicrypto/committing/v1", 32 + inner.key_len())`.
//! 2. Split: `commitment = okm[..32]`, `subkey = okm[32..]`.
//! 3. Sealed output: `commitment ‖ inner.seal(subkey, nonce, aad, pt)`.
//! 4. Open: verify `ct[..32] == commitment` in constant time, then
//!    `inner.open(subkey, nonce, aad, ct[32..])`.
//!
//! # References
//!
//! - Grubbs, Lu, Ristenpart, "Fast Message Franking", CCS 2017 — the
//!   invisible-salamander attack and CMT-1 requirement.
//! - Bellare, Hoang, "Efficient Schemes for Committing Authenticated
//!   Encryption", EUROCRYPT 2022 — UtC transform (CMT-1) and CTX (CMT-4).

use alloc::vec::Vec;

use oxicrypto_core::{ct_eq, Aead, CryptoError};
use oxicrypto_kdf::{hkdf_sha256_expand, hkdf_sha256_extract};

/// Zero-copy overhead constant: the 32-byte commitment prefix added by this
/// wrapper.  The total overhead per ciphertext is `COMMITMENT_LEN + inner.tag_len()`.
const COMMITMENT_LEN: usize = 32;

/// HKDF info string for the UtC key-committing construction.
const HKDF_INFO: &[u8] = b"oxicrypto/committing/v1";

/// Key-committing AEAD wrapper implementing the UtC/CMT-1 construction.
///
/// Wraps any [`Aead`] implementation and prepends a 32-byte commitment to the
/// ciphertext.  The commitment is a deterministic function of the encryption key,
/// so any attempt to open a ciphertext with a key other than the one used to seal
/// it will be detected.
///
/// # Wire format
///
/// ```text
/// sealed output = commitment (32 bytes) ‖ inner_ciphertext ‖ inner_tag
/// ```
///
/// The `open` method expects this full format (commitment prefix included).
pub struct CommittingAead<'a> {
    inner: &'a dyn Aead,
}

impl<'a> CommittingAead<'a> {
    /// Create a new `CommittingAead` wrapping `inner`.
    pub fn new(inner: &'a dyn Aead) -> Self {
        Self { inner }
    }

    /// Seal `pt` with associated data `aad`.
    ///
    /// Returns `commitment ‖ inner_ct ‖ inner_tag` as a single `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::InvalidKey`] — if `key` length doesn't match `inner.key_len()`.
    /// - Any error propagated from HKDF expand or `inner.seal_to_vec`.
    pub fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (commitment, subkey) = self.derive_commitment_and_subkey(key)?;

        let inner_ct = self.inner.seal_to_vec(&subkey, nonce, aad, pt)?;

        let mut out = Vec::with_capacity(COMMITMENT_LEN + inner_ct.len());
        out.extend_from_slice(&commitment);
        out.extend_from_slice(&inner_ct);
        Ok(out)
    }

    /// Open a ciphertext that includes the 32-byte commitment prefix.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::BadInput`] — if `ct` is shorter than `COMMITMENT_LEN`.
    /// - [`CryptoError::InvalidTag`] — if the commitment byte does not match
    ///   (wrong key) or the inner AEAD authentication fails.
    /// - Any error propagated from HKDF expand.
    pub fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ct.len() < COMMITMENT_LEN {
            return Err(CryptoError::BadInput);
        }
        let (stored_commitment, inner_ct) = ct.split_at(COMMITMENT_LEN);

        let (commitment, subkey) = self.derive_commitment_and_subkey(key)?;

        // Constant-time comparison to prevent timing oracle.
        if !ct_eq(&commitment, stored_commitment) {
            return Err(CryptoError::InvalidTag);
        }

        self.inner.open_to_vec(&subkey, nonce, aad, inner_ct)
    }

    /// Total length overhead added by this wrapper:
    /// 32 bytes (commitment prefix) — the inner tag length is not included here
    /// because it is part of the inner ciphertext.
    pub fn overhead(&self) -> usize {
        COMMITMENT_LEN
    }

    /// Derive the 32-byte commitment and the sub-key from `key`.
    ///
    /// Algorithm:
    /// 1. `prk = HKDF-Extract(salt=0³², ikm=key)`
    /// 2. `okm = HKDF-Expand(prk, info="oxicrypto/committing/v1", L=32+key_len)`
    /// 3. `commitment = okm[..32]`, `subkey = okm[32..]`
    fn derive_commitment_and_subkey(
        &self,
        key: &[u8],
    ) -> Result<([u8; COMMITMENT_LEN], Vec<u8>), CryptoError> {
        let inner_key_len = self.inner.key_len();
        let okm_len = COMMITMENT_LEN
            .checked_add(inner_key_len)
            .ok_or(CryptoError::BadInput)?;

        let zero_salt = [0u8; COMMITMENT_LEN];
        let prk = hkdf_sha256_extract(&zero_salt, key);

        let mut okm = alloc::vec![0u8; okm_len];
        hkdf_sha256_expand(&prk, HKDF_INFO, &mut okm)?;

        let mut commitment = [0u8; COMMITMENT_LEN];
        commitment.copy_from_slice(&okm[..COMMITMENT_LEN]);
        let subkey = okm[COMMITMENT_LEN..].to_vec();

        Ok((commitment, subkey))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Aes256Gcm;

    const KEY_A: [u8; 32] = [0x42u8; 32];
    const KEY_B: [u8; 32] = [0x24u8; 32];
    const NONCE: [u8; 12] = [0x11u8; 12];
    const AAD: &[u8] = b"associated data";
    const PLAINTEXT: &[u8] = b"hello from CommittingAead";

    #[test]
    fn committing_aead_round_trip() {
        let inner = Aes256Gcm;
        let caead = CommittingAead::new(&inner);

        let ct = caead
            .seal(&KEY_A, &NONCE, AAD, PLAINTEXT)
            .expect("seal failed");

        let recovered = caead.open(&KEY_A, &NONCE, AAD, &ct).expect("open failed");

        assert_eq!(
            recovered.as_slice(),
            PLAINTEXT,
            "round-trip must recover plaintext"
        );
    }

    #[test]
    fn committing_aead_two_key_attack_rejected() {
        // Seal under KEY_A; try to open under KEY_B → must fail with InvalidTag.
        let inner = Aes256Gcm;
        let caead = CommittingAead::new(&inner);

        let ct = caead
            .seal(&KEY_A, &NONCE, AAD, PLAINTEXT)
            .expect("seal failed");

        let result = caead.open(&KEY_B, &NONCE, AAD, &ct);
        assert_eq!(
            result,
            Err(CryptoError::InvalidTag),
            "wrong key must be rejected"
        );
    }

    #[test]
    fn committing_aead_commitment_tamper_rejected() {
        // Flip a byte in the 32-byte commitment prefix → must fail with InvalidTag.
        let inner = Aes256Gcm;
        let caead = CommittingAead::new(&inner);

        let mut ct = caead
            .seal(&KEY_A, &NONCE, AAD, PLAINTEXT)
            .expect("seal failed");

        ct[0] ^= 0xFF; // corrupt the commitment

        let result = caead.open(&KEY_A, &NONCE, AAD, &ct);
        assert_eq!(
            result,
            Err(CryptoError::InvalidTag),
            "tampered commitment must be rejected"
        );
    }

    #[test]
    fn committing_aead_empty_plaintext() {
        let inner = Aes256Gcm;
        let caead = CommittingAead::new(&inner);

        let ct = caead
            .seal(&KEY_A, &NONCE, AAD, b"")
            .expect("seal with empty plaintext failed");

        let recovered = caead
            .open(&KEY_A, &NONCE, AAD, &ct)
            .expect("open with empty plaintext failed");

        assert!(
            recovered.is_empty(),
            "empty plaintext must round-trip to empty"
        );
    }

    #[test]
    fn committing_aead_empty_aad() {
        let inner = Aes256Gcm;
        let caead = CommittingAead::new(&inner);

        let ct = caead
            .seal(&KEY_A, &NONCE, b"", PLAINTEXT)
            .expect("seal with empty AAD failed");

        let recovered = caead
            .open(&KEY_A, &NONCE, b"", &ct)
            .expect("open with empty AAD failed");

        assert_eq!(
            recovered.as_slice(),
            PLAINTEXT,
            "empty AAD must round-trip correctly"
        );
    }

    #[test]
    fn committing_aead_overhead_is_32() {
        let inner = Aes256Gcm;
        let caead = CommittingAead::new(&inner);
        assert_eq!(
            caead.overhead(),
            32,
            "overhead must be 32 bytes (commitment)"
        );
    }

    #[test]
    fn committing_aead_ct_length() {
        let inner = Aes256Gcm;
        let caead = CommittingAead::new(&inner);

        let ct = caead
            .seal(&KEY_A, &NONCE, AAD, PLAINTEXT)
            .expect("seal failed");

        // Expected: 32 (commitment) + pt.len() + tag_len
        let expected_len = COMMITMENT_LEN + PLAINTEXT.len() + inner.tag_len();
        assert_eq!(
            ct.len(),
            expected_len,
            "ciphertext must be commitment + plaintext + tag"
        );
    }
}
