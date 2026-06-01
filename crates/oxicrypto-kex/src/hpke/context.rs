//! The HPKE encryption context (RFC 9180 §5.2) — stateful `Seal`/`Open`/`Export`.
//!
//! Setup produces a directional context: senders receive an [`HpkeContextS`]
//! (seal + export) and recipients an [`HpkeContextR`] (open + export). Both wrap
//! the same private inner context; splitting them at the type level makes a
//! recipient calling `seal` (or vice-versa) a compile error.
//!
//! Nonces are computed as `base_nonce XOR I2OSP(seq, Nn)` with a strictly
//! increasing per-context sequence number; the spec's overflow guard
//! (`seq >= (1 << (8*Nn)) - 1`) is enforced before each operation.

use oxicrypto_core::{Aead, CryptoError};

use super::ids::AeadId;
use super::labeled::HpkeKdf;

/// The AEAD used by an encryption context.
///
/// An enum rather than a `Box<dyn Aead>` so that the export-only pseudo-AEAD
/// (which has no key, nonce, or `Seal`/`Open`) is modelled directly and no
/// per-context heap allocation is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeAead {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20Poly1305.
    ChaCha20Poly1305,
    /// Export-only: `Seal`/`Open` are unsupported.
    ExportOnly,
}

impl HpkeAead {
    /// Map an [`AeadId`] to the context AEAD.
    #[must_use]
    pub const fn from_id(id: AeadId) -> Self {
        match id {
            AeadId::Aes128Gcm => HpkeAead::Aes128Gcm,
            AeadId::Aes256Gcm => HpkeAead::Aes256Gcm,
            AeadId::ChaCha20Poly1305 => HpkeAead::ChaCha20Poly1305,
            AeadId::ExportOnly => HpkeAead::ExportOnly,
        }
    }

    /// Whether this is the export-only pseudo-AEAD (no `Seal`/`Open`).
    #[must_use]
    const fn is_export_only(self) -> bool {
        matches!(self, HpkeAead::ExportOnly)
    }

    /// `Seal(key, nonce, aad, pt)` — dispatch to the concrete AEAD.
    fn seal(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match self {
            HpkeAead::Aes128Gcm => oxicrypto_aead::Aes128Gcm.seal(key, nonce, aad, pt, ct_out),
            HpkeAead::Aes256Gcm => oxicrypto_aead::Aes256Gcm.seal(key, nonce, aad, pt, ct_out),
            HpkeAead::ChaCha20Poly1305 => {
                oxicrypto_aead::ChaCha20Poly1305.seal(key, nonce, aad, pt, ct_out)
            }
            HpkeAead::ExportOnly => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    /// `Open(key, nonce, aad, ct)` — dispatch to the concrete AEAD.
    fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match self {
            HpkeAead::Aes128Gcm => oxicrypto_aead::Aes128Gcm.open(key, nonce, aad, ct, pt_out),
            HpkeAead::Aes256Gcm => oxicrypto_aead::Aes256Gcm.open(key, nonce, aad, ct, pt_out),
            HpkeAead::ChaCha20Poly1305 => {
                oxicrypto_aead::ChaCha20Poly1305.open(key, nonce, aad, ct, pt_out)
            }
            HpkeAead::ExportOnly => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

/// Shared, direction-agnostic context state (RFC 9180 §5.2).
struct ContextInner {
    aead: HpkeAead,
    kdf: HpkeKdf,
    suite_id: Vec<u8>,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    seq: u128,
    nn: usize,
    nt: usize,
}

impl ContextInner {
    /// `ComputeNonce(seq) = base_nonce XOR I2OSP(seq, Nn)` (RFC 9180 §5.2).
    fn compute_nonce(&self) -> Vec<u8> {
        let seq_be = self.seq.to_be_bytes(); // 16 bytes, big-endian
        let mut nonce = self.base_nonce.clone();
        // XOR the Nn-byte big-endian sequence number into the low bytes.
        // Nn <= 12 < 16, so the last Nn bytes of seq_be carry all set bits.
        let start = seq_be.len() - self.nn;
        for i in 0..self.nn {
            nonce[i] ^= seq_be[start + i];
        }
        nonce
    }

    /// `IncrementSeq` with the spec overflow guard (RFC 9180 §5.2).
    ///
    /// The guard `seq >= (1 << (8*Nn)) - 1` is checked **before** the operation
    /// that consumes the current sequence number.
    fn check_no_overflow(&self) -> Result<(), CryptoError> {
        // 8 * Nn fits in 128 only when Nn <= 16; Nn is 12 here, so the shift is
        // always valid. Guard defensively anyway.
        let bits = 8usize.saturating_mul(self.nn);
        if bits >= 128 {
            // The counter space exceeds u128; overflow is unreachable.
            return Ok(());
        }
        let limit = (1u128 << bits) - 1;
        if self.seq >= limit {
            return Err(CryptoError::Kex);
        }
        Ok(())
    }

    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Export-only suites have no Seal/Open; reject before nonce logic
        // (Nn = 0 would otherwise spuriously trip the overflow guard).
        if self.aead.is_export_only() {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        self.check_no_overflow()?;
        let nonce = self.compute_nonce();
        let mut ct = vec![0u8; pt.len() + self.nt];
        let written = self.aead.seal(&self.key, &nonce, aad, pt, &mut ct)?;
        ct.truncate(written);
        // Only advance the sequence number on success.
        self.seq += 1;
        Ok(ct)
    }

    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.aead.is_export_only() {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        self.check_no_overflow()?;
        if ct.len() < self.nt {
            return Err(CryptoError::InvalidTag);
        }
        let nonce = self.compute_nonce();
        let mut pt = vec![0u8; ct.len() - self.nt];
        let written = self.aead.open(&self.key, &nonce, aad, ct, &mut pt)?;
        pt.truncate(written);
        self.seq += 1;
        Ok(pt)
    }

    /// `Export(exporter_context, L)` (RFC 9180 §5.3).
    fn export(&self, exporter_context: &[u8], l: usize) -> Result<Vec<u8>, CryptoError> {
        self.kdf.labeled_expand(
            &self.suite_id,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            l,
        )
    }
}

/// Material required to construct an encryption context, produced by the suite
/// from a key-schedule result. Internal to the crate.
pub(crate) struct ContextConfig {
    /// The negotiated AEAD.
    pub aead: HpkeAead,
    /// The key schedule's KDF (used by `Export`).
    pub kdf: HpkeKdf,
    /// The HPKE `suite_id`.
    pub suite_id: Vec<u8>,
    /// AEAD key (`Nk` bytes; empty for export-only).
    pub key: Vec<u8>,
    /// Base nonce (`Nn` bytes; empty for export-only).
    pub base_nonce: Vec<u8>,
    /// Exporter secret (`Nh` bytes).
    pub exporter_secret: Vec<u8>,
    /// AEAD nonce length `Nn`.
    pub nn: usize,
    /// AEAD tag length `Nt`.
    pub nt: usize,
}

impl ContextInner {
    /// Build the inner context (sequence number initialised to zero).
    fn from_config(config: ContextConfig) -> Self {
        ContextInner {
            aead: config.aead,
            kdf: config.kdf,
            suite_id: config.suite_id,
            key: config.key,
            base_nonce: config.base_nonce,
            exporter_secret: config.exporter_secret,
            seq: 0,
            nn: config.nn,
            nt: config.nt,
        }
    }
}

/// Sender-side HPKE context: `Seal` + `Export` (RFC 9180 §5.2).
pub struct HpkeContextS {
    inner: ContextInner,
}

impl HpkeContextS {
    /// Construct from key-schedule material. Internal to the crate.
    pub(crate) fn new(config: ContextConfig) -> Self {
        Self {
            inner: ContextInner::from_config(config),
        }
    }

    /// `Seal(aad, pt)` — encrypt `pt`, returning ciphertext ‖ tag.
    ///
    /// The internal sequence number advances by one on success.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`] for an export-only suite,
    /// [`CryptoError::Kex`] if the sequence number would overflow, and propagates
    /// AEAD errors.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.seal(aad, pt)
    }

    /// `Export(exporter_context, L)` — derive `L` bytes of exported secret.
    ///
    /// # Errors
    ///
    /// Propagates labeled-expand errors (e.g. `L == 0`).
    pub fn export(&self, exporter_context: &[u8], l: usize) -> Result<Vec<u8>, CryptoError> {
        self.inner.export(exporter_context, l)
    }

    /// The current sequence number (number of successful `Seal`s).
    #[must_use]
    pub fn sequence_number(&self) -> u128 {
        self.inner.seq
    }

    /// Test-only sequence-number setter, used to drive the overflow path.
    #[cfg(test)]
    pub(crate) fn set_sequence_number(&mut self, seq: u128) {
        self.inner.seq = seq;
    }
}

/// Recipient-side HPKE context: `Open` + `Export` (RFC 9180 §5.2).
pub struct HpkeContextR {
    inner: ContextInner,
}

impl HpkeContextR {
    /// Construct from key-schedule material. Internal to the crate.
    pub(crate) fn new(config: ContextConfig) -> Self {
        Self {
            inner: ContextInner::from_config(config),
        }
    }

    /// `Open(aad, ct)` — decrypt `ct` (ciphertext ‖ tag), returning plaintext.
    ///
    /// The internal sequence number advances by one on success; it is **not**
    /// advanced on authentication failure, matching RFC 9180 §5.2.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`] for an export-only suite,
    /// [`CryptoError::InvalidTag`] on authentication failure,
    /// [`CryptoError::Kex`] on sequence-number overflow.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.open(aad, ct)
    }

    /// `Export(exporter_context, L)` — derive `L` bytes of exported secret.
    ///
    /// # Errors
    ///
    /// Propagates labeled-expand errors (e.g. `L == 0`).
    pub fn export(&self, exporter_context: &[u8], l: usize) -> Result<Vec<u8>, CryptoError> {
        self.inner.export(exporter_context, l)
    }

    /// The current sequence number (number of successful `Open`s).
    #[must_use]
    pub fn sequence_number(&self) -> u128 {
        self.inner.seq
    }
}

#[cfg(test)]
mod context_tests {
    use super::*;

    #[test]
    fn export_only_aead_rejects_seal_open() {
        assert_eq!(
            HpkeAead::ExportOnly.seal(&[], &[], &[], &[], &mut []),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        assert_eq!(
            HpkeAead::ExportOnly.open(&[], &[], &[], &[], &mut []),
            Err(CryptoError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn from_id_mapping() {
        assert_eq!(HpkeAead::from_id(AeadId::Aes128Gcm), HpkeAead::Aes128Gcm);
        assert_eq!(HpkeAead::from_id(AeadId::Aes256Gcm), HpkeAead::Aes256Gcm);
        assert_eq!(
            HpkeAead::from_id(AeadId::ChaCha20Poly1305),
            HpkeAead::ChaCha20Poly1305
        );
        assert_eq!(HpkeAead::from_id(AeadId::ExportOnly), HpkeAead::ExportOnly);
    }

    // ComputeNonce: seq 0 → base_nonce; seq 1 → base_nonce with last byte XOR 1.
    #[test]
    fn compute_nonce_matches_xor() {
        let base = vec![
            0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x7d,
        ];
        let inner = ContextInner {
            aead: HpkeAead::Aes128Gcm,
            kdf: HpkeKdf::HkdfSha256,
            suite_id: Vec::new(),
            key: vec![0u8; 16],
            base_nonce: base.clone(),
            exporter_secret: vec![0u8; 32],
            seq: 0,
            nn: 12,
            nt: 16,
        };
        assert_eq!(inner.compute_nonce(), base);

        let mut inner1 = inner;
        inner1.seq = 1;
        let mut expected = base.clone();
        let last = expected.len() - 1;
        expected[last] ^= 0x01;
        assert_eq!(inner1.compute_nonce(), expected);
    }
}
