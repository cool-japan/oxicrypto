//! HPKE algorithm identifiers, `I2OSP`, suite-id builders, and length constants
//! (RFC 9180 §7).
//!
//! Three identifier spaces are defined by RFC 9180:
//!
//! * [`KemId`]   — the KEM (Key Encapsulation Mechanism), §7.1.
//! * [`KdfId`]   — the KDF used by the key schedule, §7.2.
//! * [`AeadId`]  — the AEAD used by the encryption context, §7.3.
//!
//! Two distinct `suite_id` byte strings are derived from these identifiers and
//! are used as domain-separation tags for the labeled HKDF (see
//! [`crate::hpke::labeled`]):
//!
//! * the **KEM** suite id  — `"KEM" ‖ I2OSP(kem_id, 2)` (used only inside the KEM), and
//! * the **HPKE** suite id — `"HPKE" ‖ I2OSP(kem_id, 2) ‖ I2OSP(kdf_id, 2) ‖ I2OSP(aead_id, 2)`
//!   (used by the key schedule and the encryption context).

/// Key Encapsulation Mechanism identifier (RFC 9180 §7.1).
///
/// Only the two KEMs implemented by this crate are enumerated; the type is
/// `#[non_exhaustive]` so additional KEMs (P-384/P-521/X448) can be added
/// without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KemId {
    /// DHKEM(P-256, HKDF-SHA256) — `0x0010`.
    DhkemP256HkdfSha256,
    /// DHKEM(X25519, HKDF-SHA256) — `0x0020`.
    DhkemX25519HkdfSha256,
}

impl KemId {
    /// The 16-bit wire identifier for this KEM (RFC 9180 Table 2).
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            KemId::DhkemP256HkdfSha256 => 0x0010,
            KemId::DhkemX25519HkdfSha256 => 0x0020,
        }
    }

    /// `Nsecret` — length in bytes of the KEM shared secret.
    #[must_use]
    pub const fn n_secret(self) -> usize {
        match self {
            // Both KEMs derive a 32-byte shared secret via HKDF-SHA256.
            KemId::DhkemP256HkdfSha256 | KemId::DhkemX25519HkdfSha256 => 32,
        }
    }

    /// `Nenc` — length in bytes of an encapsulated key (serialized ephemeral
    /// public key).
    ///
    /// P-256 uses **uncompressed** SEC1 encoding (65 bytes); X25519 is 32 bytes.
    #[must_use]
    pub const fn n_enc(self) -> usize {
        match self {
            KemId::DhkemP256HkdfSha256 => 65,
            KemId::DhkemX25519HkdfSha256 => 32,
        }
    }

    /// `Npk` — length in bytes of a serialized public key.
    ///
    /// For the DHKEMs of this crate `Npk == Nenc`.
    #[must_use]
    pub const fn n_pk(self) -> usize {
        self.n_enc()
    }

    /// `Nsk` — length in bytes of a serialized private key (raw scalar).
    #[must_use]
    pub const fn n_sk(self) -> usize {
        match self {
            KemId::DhkemP256HkdfSha256 | KemId::DhkemX25519HkdfSha256 => 32,
        }
    }
}

/// Key Derivation Function identifier (RFC 9180 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfId {
    /// HKDF-SHA256 — `0x0001`.
    HkdfSha256,
    /// HKDF-SHA384 — `0x0002`.
    HkdfSha384,
    /// HKDF-SHA512 — `0x0003`.
    HkdfSha512,
}

impl KdfId {
    /// The 16-bit wire identifier for this KDF (RFC 9180 Table 3).
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            KdfId::HkdfSha256 => 0x0001,
            KdfId::HkdfSha384 => 0x0002,
            KdfId::HkdfSha512 => 0x0003,
        }
    }

    /// `Nh` — output length in bytes of the underlying hash (the extract size).
    #[must_use]
    pub const fn n_h(self) -> usize {
        match self {
            KdfId::HkdfSha256 => 32,
            KdfId::HkdfSha384 => 48,
            KdfId::HkdfSha512 => 64,
        }
    }
}

/// AEAD identifier (RFC 9180 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadId {
    /// AES-128-GCM — `0x0001`.
    Aes128Gcm,
    /// AES-256-GCM — `0x0002`.
    Aes256Gcm,
    /// ChaCha20Poly1305 — `0x0003`.
    ChaCha20Poly1305,
    /// Export-only — `0xFFFF`. No `Seal`/`Open`; the context supports `Export` only.
    ExportOnly,
}

impl AeadId {
    /// The 16-bit wire identifier for this AEAD (RFC 9180 Table 5).
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            AeadId::Aes128Gcm => 0x0001,
            AeadId::Aes256Gcm => 0x0002,
            AeadId::ChaCha20Poly1305 => 0x0003,
            AeadId::ExportOnly => 0xFFFF,
        }
    }

    /// `Nk` — AEAD key length in bytes (`0` for export-only).
    #[must_use]
    pub const fn n_k(self) -> usize {
        match self {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm | AeadId::ChaCha20Poly1305 => 32,
            AeadId::ExportOnly => 0,
        }
    }

    /// `Nn` — AEAD nonce length in bytes (`0` for export-only).
    #[must_use]
    pub const fn n_n(self) -> usize {
        match self {
            AeadId::Aes128Gcm | AeadId::Aes256Gcm | AeadId::ChaCha20Poly1305 => 12,
            AeadId::ExportOnly => 0,
        }
    }

    /// `Nt` — AEAD authentication-tag length in bytes (`0` for export-only).
    #[must_use]
    pub const fn n_t(self) -> usize {
        match self {
            AeadId::Aes128Gcm | AeadId::Aes256Gcm | AeadId::ChaCha20Poly1305 => 16,
            AeadId::ExportOnly => 0,
        }
    }
}

/// `I2OSP(n, w)` — encode the non-negative integer `n` as a big-endian octet
/// string of length `w` (RFC 8017 §4.1).
///
/// Only `w <= 16` is required by HPKE; this helper supports any `w` by
/// taking the low `w` bytes of the 128-bit big-endian encoding of `n`.
#[must_use]
pub fn i2osp(n: u128, w: usize) -> Vec<u8> {
    let be = n.to_be_bytes();
    let mut out = vec![0u8; w];
    // Copy the least-significant `min(w, 16)` bytes, right-aligned.
    let take = core::cmp::min(w, be.len());
    out[w - take..].copy_from_slice(&be[be.len() - take..]);
    out
}

/// Build the **KEM** `suite_id`: `"KEM" ‖ I2OSP(kem_id, 2)` (RFC 9180 §4.1).
#[must_use]
pub fn kem_suite_id(kem: KemId) -> Vec<u8> {
    let mut id = Vec::with_capacity(5);
    id.extend_from_slice(b"KEM");
    id.extend_from_slice(&i2osp(u128::from(kem.id()), 2));
    id
}

/// Build the **HPKE** `suite_id`:
/// `"HPKE" ‖ I2OSP(kem_id, 2) ‖ I2OSP(kdf_id, 2) ‖ I2OSP(aead_id, 2)`
/// (RFC 9180 §5.1).
#[must_use]
pub fn hpke_suite_id(kem: KemId, kdf: KdfId, aead: AeadId) -> Vec<u8> {
    let mut id = Vec::with_capacity(10);
    id.extend_from_slice(b"HPKE");
    id.extend_from_slice(&i2osp(u128::from(kem.id()), 2));
    id.extend_from_slice(&i2osp(u128::from(kdf.id()), 2));
    id.extend_from_slice(&i2osp(u128::from(aead.id()), 2));
    id
}

#[cfg(test)]
mod ids_tests {
    use super::*;

    #[test]
    fn i2osp_basic_values() {
        assert_eq!(i2osp(0, 1), vec![0x00]);
        assert_eq!(i2osp(0, 2), vec![0x00, 0x00]);
        assert_eq!(i2osp(1, 1), vec![0x01]);
        assert_eq!(i2osp(255, 1), vec![0xff]);
        assert_eq!(i2osp(256, 2), vec![0x01, 0x00]);
        assert_eq!(i2osp(0x0010, 2), vec![0x00, 0x10]);
        assert_eq!(i2osp(0x0020, 2), vec![0x00, 0x20]);
        assert_eq!(i2osp(0xFFFF, 2), vec![0xff, 0xff]);
        assert_eq!(i2osp(32, 2), vec![0x00, 0x20]);
    }

    #[test]
    fn i2osp_wider_than_input() {
        // 4-byte encoding of 1 must be left-padded with zeros.
        assert_eq!(i2osp(1, 4), vec![0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn kem_suite_id_bytes() {
        // "KEM" = 0x4b 0x45 0x4d
        assert_eq!(
            kem_suite_id(KemId::DhkemX25519HkdfSha256),
            vec![0x4b, 0x45, 0x4d, 0x00, 0x20]
        );
        assert_eq!(
            kem_suite_id(KemId::DhkemP256HkdfSha256),
            vec![0x4b, 0x45, 0x4d, 0x00, 0x10]
        );
    }

    #[test]
    fn hpke_suite_id_bytes() {
        // "HPKE" = 0x48 0x50 0x4b 0x45
        let id = hpke_suite_id(
            KemId::DhkemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::Aes128Gcm,
        );
        assert_eq!(
            id,
            vec![0x48, 0x50, 0x4b, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01]
        );
    }

    #[test]
    fn identifier_values() {
        assert_eq!(KemId::DhkemP256HkdfSha256.id(), 0x0010);
        assert_eq!(KemId::DhkemX25519HkdfSha256.id(), 0x0020);
        assert_eq!(KdfId::HkdfSha256.id(), 1);
        assert_eq!(KdfId::HkdfSha384.id(), 2);
        assert_eq!(KdfId::HkdfSha512.id(), 3);
        assert_eq!(AeadId::Aes128Gcm.id(), 1);
        assert_eq!(AeadId::Aes256Gcm.id(), 2);
        assert_eq!(AeadId::ChaCha20Poly1305.id(), 3);
        assert_eq!(AeadId::ExportOnly.id(), 0xFFFF);
    }

    #[test]
    fn length_constants() {
        assert_eq!(KemId::DhkemX25519HkdfSha256.n_enc(), 32);
        assert_eq!(KemId::DhkemX25519HkdfSha256.n_pk(), 32);
        assert_eq!(KemId::DhkemX25519HkdfSha256.n_sk(), 32);
        assert_eq!(KemId::DhkemX25519HkdfSha256.n_secret(), 32);
        assert_eq!(KemId::DhkemP256HkdfSha256.n_enc(), 65);
        assert_eq!(KemId::DhkemP256HkdfSha256.n_pk(), 65);
        assert_eq!(KemId::DhkemP256HkdfSha256.n_sk(), 32);
        assert_eq!(KemId::DhkemP256HkdfSha256.n_secret(), 32);

        assert_eq!(KdfId::HkdfSha256.n_h(), 32);
        assert_eq!(KdfId::HkdfSha384.n_h(), 48);
        assert_eq!(KdfId::HkdfSha512.n_h(), 64);

        assert_eq!(AeadId::Aes128Gcm.n_k(), 16);
        assert_eq!(AeadId::Aes128Gcm.n_n(), 12);
        assert_eq!(AeadId::Aes128Gcm.n_t(), 16);
        assert_eq!(AeadId::Aes256Gcm.n_k(), 32);
        assert_eq!(AeadId::ChaCha20Poly1305.n_k(), 32);
        assert_eq!(AeadId::ExportOnly.n_k(), 0);
        assert_eq!(AeadId::ExportOnly.n_n(), 0);
        assert_eq!(AeadId::ExportOnly.n_t(), 0);
    }
}
