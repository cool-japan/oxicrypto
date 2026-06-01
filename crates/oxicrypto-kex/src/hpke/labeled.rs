//! Labeled HKDF (`LabeledExtract` / `LabeledExpand`) per RFC 9180 §4.
//!
//! HPKE never calls a raw KDF directly; every extraction and expansion is
//! domain-separated with the protocol-version string `"HPKE-v1"`, a `suite_id`
//! (see [`crate::hpke::ids`]), and an ASCII `label`:
//!
//! ```text
//! LabeledExtract(salt, label, ikm) =
//!     Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm)
//!
//! LabeledExpand(prk, label, info, L) =
//!     Expand(prk, I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L)
//! ```
//!
//! Because the three SHA-2 variants produce PRKs of different lengths, the KDF
//! is modelled as an `enum` ([`HpkeKdf`]) rather than a trait object: each
//! variant dispatches to the corresponding separated extract/expand pair in
//! `oxicrypto-kdf`.

use oxicrypto_core::CryptoError;
use oxicrypto_kdf::{
    hkdf_sha256_expand, hkdf_sha256_extract, hkdf_sha384_expand, hkdf_sha384_extract,
    hkdf_sha512_expand, hkdf_sha512_extract,
};

use super::ids::i2osp;

/// The HPKE protocol-version label prefixed to every labeled HKDF input.
const HPKE_V1: &[u8] = b"HPKE-v1";

/// An HKDF instance selected by the HPKE KDF id, exposing the labeled
/// extract/expand primitives of RFC 9180 §4.
///
/// Used both by the KEM (with the KEM `suite_id` and HKDF-SHA256) and by the
/// key schedule / exporter (with the HPKE `suite_id` and the user-chosen KDF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKdf {
    /// HKDF-SHA256 (`Nh = 32`).
    HkdfSha256,
    /// HKDF-SHA384 (`Nh = 48`).
    HkdfSha384,
    /// HKDF-SHA512 (`Nh = 64`).
    HkdfSha512,
}

impl HpkeKdf {
    /// `Nh` — the extract output length (and PRK length) in bytes.
    #[must_use]
    pub const fn nh(self) -> usize {
        match self {
            HpkeKdf::HkdfSha256 => 32,
            HpkeKdf::HkdfSha384 => 48,
            HpkeKdf::HkdfSha512 => 64,
        }
    }

    /// `Extract(salt, ikm)` — RFC 5869 extraction, returning an `Nh`-byte PRK.
    #[must_use]
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            HpkeKdf::HkdfSha256 => hkdf_sha256_extract(salt, ikm).to_vec(),
            HpkeKdf::HkdfSha384 => hkdf_sha384_extract(salt, ikm).to_vec(),
            HpkeKdf::HkdfSha512 => hkdf_sha512_extract(salt, ikm).to_vec(),
        }
    }

    /// `Expand(prk, info, L)` — RFC 5869 expansion into `out` (`L = out.len()`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if `prk` is rejected by the backend or `out` is
    /// empty / longer than `255 * Nh`.
    pub fn expand(self, prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            HpkeKdf::HkdfSha256 => hkdf_sha256_expand(prk, info, out),
            HpkeKdf::HkdfSha384 => hkdf_sha384_expand(prk, info, out),
            HpkeKdf::HkdfSha512 => hkdf_sha512_expand(prk, info, out),
        }
    }

    /// `LabeledExtract(salt, label, ikm)` (RFC 9180 §4):
    /// `Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm)`.
    #[must_use]
    pub fn labeled_extract(
        self,
        suite_id: &[u8],
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Vec<u8> {
        let mut labeled_ikm =
            Vec::with_capacity(HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(HPKE_V1);
        labeled_ikm.extend_from_slice(suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);
        self.extract(salt, &labeled_ikm)
    }

    /// `LabeledExpand(prk, label, info, L)` (RFC 9180 §4):
    /// `Expand(prk, I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L)`.
    ///
    /// Returns the `L`-byte output as an owned vector.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BadInput`] if `l == 0`, or propagates an expand
    /// error (e.g. `l > 255 * Nh`).
    pub fn labeled_expand(
        self,
        suite_id: &[u8],
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        l: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        if l == 0 {
            return Err(CryptoError::BadInput);
        }
        let mut labeled_info =
            Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
        labeled_info.extend_from_slice(&i2osp(l as u128, 2));
        labeled_info.extend_from_slice(HPKE_V1);
        labeled_info.extend_from_slice(suite_id);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);

        let mut out = vec![0u8; l];
        self.expand(prk, &labeled_info, &mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod labeled_tests {
    use super::*;
    use crate::hpke::ids::{hpke_suite_id, AeadId, KdfId, KemId};

    // Reconstruct LabeledExtract/Expand from the raw primitives and confirm the
    // enum produces an identical result, so the labeling wiring is verified
    // independently of the higher-level KEM/key-schedule KATs.
    #[test]
    fn labeled_extract_matches_manual_construction() {
        let suite = hpke_suite_id(
            KemId::DhkemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::Aes128Gcm,
        );
        let salt = b"";
        let label = b"info_hash";
        let ikm = b"some info string";

        let got = HpkeKdf::HkdfSha256.labeled_extract(&suite, salt, label, ikm);

        let mut manual = Vec::new();
        manual.extend_from_slice(b"HPKE-v1");
        manual.extend_from_slice(&suite);
        manual.extend_from_slice(label);
        manual.extend_from_slice(ikm);
        let expected = hkdf_sha256_extract(salt, &manual).to_vec();

        assert_eq!(got, expected);
        assert_eq!(got.len(), 32);
    }

    #[test]
    fn labeled_expand_matches_manual_construction() {
        let suite = hpke_suite_id(
            KemId::DhkemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::Aes128Gcm,
        );
        let prk = [0x07u8; 32];
        let label = b"key";
        let info = b"context bytes";
        let l = 16usize;

        let got = HpkeKdf::HkdfSha256
            .labeled_expand(&suite, &prk, label, info, l)
            .expect("labeled_expand");

        let mut labeled_info = Vec::new();
        labeled_info.extend_from_slice(&[0x00, 0x10]); // I2OSP(16, 2)
        labeled_info.extend_from_slice(b"HPKE-v1");
        labeled_info.extend_from_slice(&suite);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);
        let mut expected = [0u8; 16];
        hkdf_sha256_expand(&prk, &labeled_info, &mut expected).expect("expand");

        assert_eq!(got, expected.to_vec());
    }

    #[test]
    fn labeled_expand_zero_length_is_bad_input() {
        let suite = hpke_suite_id(
            KemId::DhkemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::Aes128Gcm,
        );
        let prk = [0x07u8; 32];
        let result = HpkeKdf::HkdfSha256.labeled_expand(&suite, &prk, b"key", b"", 0);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn nh_values() {
        assert_eq!(HpkeKdf::HkdfSha256.nh(), 32);
        assert_eq!(HpkeKdf::HkdfSha384.nh(), 48);
        assert_eq!(HpkeKdf::HkdfSha512.nh(), 64);
    }
}
