//! The HPKE key schedule (RFC 9180 §5.1) for all four modes.
//!
//! `KeySchedule(mode, shared_secret, info, psk, psk_id)` mixes the KEM shared
//! secret with the application `info` and an optional pre-shared key to derive
//! the encryption-context triple `(key, base_nonce, exporter_secret)`.
//!
//! Unlike the KEM, the key schedule uses the **HPKE** `suite_id` and the
//! user-selected KDF (see [`crate::hpke::labeled::HpkeKdf`]).

use oxicrypto_core::CryptoError;

use super::ids::i2osp;
use super::labeled::HpkeKdf;

/// HPKE establishment mode (RFC 9180 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HpkeMode {
    /// Base — no sender authentication, no pre-shared key. `mode = 0x00`.
    Base,
    /// PSK — pre-shared-key authentication. `mode = 0x01`.
    Psk,
    /// Auth — asymmetric sender authentication. `mode = 0x02`.
    Auth,
    /// AuthPSK — both PSK and asymmetric authentication. `mode = 0x03`.
    AuthPsk,
}

impl HpkeMode {
    /// The single-byte mode identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            HpkeMode::Base => 0x00,
            HpkeMode::Psk => 0x01,
            HpkeMode::Auth => 0x02,
            HpkeMode::AuthPsk => 0x03,
        }
    }

    /// Whether this mode requires a (non-empty) pre-shared key.
    #[must_use]
    const fn uses_psk(self) -> bool {
        matches!(self, HpkeMode::Psk | HpkeMode::AuthPsk)
    }
}

/// The output of [`key_schedule`]: the AEAD key, base nonce, and exporter secret.
#[derive(Clone)]
pub struct KeyScheduleOutput {
    /// AEAD key (`Nk` bytes); empty for the export-only AEAD.
    pub key: Vec<u8>,
    /// Base nonce (`Nn` bytes); empty for the export-only AEAD.
    pub base_nonce: Vec<u8>,
    /// Exporter secret (`Nh` bytes).
    pub exporter_secret: Vec<u8>,
}

/// `VerifyPSKInputs` (RFC 9180 §5.1).
///
/// The default PSK and PSK id are both the empty string. Base/Auth require both
/// to be empty; PSK/AuthPSK require both to be non-empty. Any other combination
/// — including supplying only one of the two — is an error.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] on an inconsistent PSK configuration.
pub fn verify_psk_inputs(mode: HpkeMode, psk: &[u8], psk_id: &[u8]) -> Result<(), CryptoError> {
    let got_psk = !psk.is_empty();
    let got_psk_id = !psk_id.is_empty();
    // A PSK without its id (or vice-versa) is always inconsistent.
    if got_psk != got_psk_id {
        return Err(CryptoError::BadInput);
    }
    // The presence of a PSK must match what the mode requires.
    if got_psk != mode.uses_psk() {
        return Err(CryptoError::BadInput);
    }
    Ok(())
}

/// Inputs to [`key_schedule`] (RFC 9180 §5.1).
///
/// `suite_id` is the **HPKE** suite id; `kdf` is the user-selected KDF; `nk`/`nn`
/// are the AEAD key/nonce lengths (`0` each for the export-only AEAD, in which
/// case `key`/`base_nonce` come back empty).
pub struct KeyScheduleParams<'a> {
    /// The user-selected KDF.
    pub kdf: HpkeKdf,
    /// The HPKE `suite_id`.
    pub suite_id: &'a [u8],
    /// The establishment mode.
    pub mode: HpkeMode,
    /// The KEM shared secret.
    pub shared_secret: &'a [u8],
    /// The application `info`.
    pub info: &'a [u8],
    /// The pre-shared key (empty unless a PSK mode).
    pub psk: &'a [u8],
    /// The pre-shared-key identifier (empty unless a PSK mode).
    pub psk_id: &'a [u8],
    /// AEAD key length `Nk` (`0` for export-only).
    pub nk: usize,
    /// AEAD nonce length `Nn` (`0` for export-only).
    pub nn: usize,
}

/// `KeySchedule(mode, shared_secret, info, psk, psk_id)` (RFC 9180 §5.1).
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if the PSK inputs are inconsistent, and
/// propagates labeled-expand errors.
pub fn key_schedule(params: KeyScheduleParams<'_>) -> Result<KeyScheduleOutput, CryptoError> {
    let KeyScheduleParams {
        kdf,
        suite_id,
        mode,
        shared_secret,
        info,
        psk,
        psk_id,
        nk,
        nn,
    } = params;

    verify_psk_inputs(mode, psk, psk_id)?;

    let psk_id_hash = kdf.labeled_extract(suite_id, b"", b"psk_id_hash", psk_id);
    let info_hash = kdf.labeled_extract(suite_id, b"", b"info_hash", info);

    // key_schedule_context = I2OSP(mode, 1) ‖ psk_id_hash ‖ info_hash
    let mut ksc = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ksc.extend_from_slice(&i2osp(u128::from(mode.id()), 1));
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", psk)
    let secret = kdf.labeled_extract(suite_id, shared_secret, b"secret", psk);

    // For export-only AEADs (Nk = Nn = 0) the key/base_nonce are not derived.
    let key = if nk == 0 {
        Vec::new()
    } else {
        kdf.labeled_expand(suite_id, &secret, b"key", &ksc, nk)?
    };
    let base_nonce = if nn == 0 {
        Vec::new()
    } else {
        kdf.labeled_expand(suite_id, &secret, b"base_nonce", &ksc, nn)?
    };
    let exporter_secret = kdf.labeled_expand(suite_id, &secret, b"exp", &ksc, kdf.nh())?;

    Ok(KeyScheduleOutput {
        key,
        base_nonce,
        exporter_secret,
    })
}

#[cfg(test)]
mod key_schedule_tests {
    use super::*;
    use crate::hpke::ids::{hpke_suite_id, AeadId, KdfId, KemId};

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex in test vector")
    }

    // RFC 9180 A.1.1 — key/base_nonce/exporter_secret from the KEM shared secret.
    #[test]
    fn key_schedule_a_1_1_base() {
        let suite = hpke_suite_id(
            KemId::DhkemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::Aes128Gcm,
        );
        let shared_secret = hx("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        let info = hx("4f6465206f6e2061204772656369616e2055726e");

        let out = key_schedule(KeyScheduleParams {
            kdf: HpkeKdf::HkdfSha256,
            suite_id: &suite,
            mode: HpkeMode::Base,
            shared_secret: &shared_secret,
            info: &info,
            psk: b"",
            psk_id: b"",
            nk: 16,
            nn: 12,
        })
        .expect("key_schedule");

        assert_eq!(out.key, hx("4531685d41d65f03dc48f6b8302c05b0"), "key");
        assert_eq!(out.base_nonce, hx("56d890e5accaaf011cff4b7d"), "base_nonce");
        assert_eq!(
            out.exporter_secret,
            hx("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"),
            "exporter_secret"
        );
    }

    #[test]
    fn verify_psk_inputs_rules() {
        // Base: both empty OK; either non-empty fails.
        assert!(verify_psk_inputs(HpkeMode::Base, b"", b"").is_ok());
        assert_eq!(
            verify_psk_inputs(HpkeMode::Base, b"psk", b""),
            Err(CryptoError::BadInput)
        );
        assert_eq!(
            verify_psk_inputs(HpkeMode::Base, b"", b"id"),
            Err(CryptoError::BadInput)
        );
        // PSK: both non-empty OK; missing one fails; both empty fails.
        assert!(verify_psk_inputs(HpkeMode::Psk, b"psk", b"id").is_ok());
        assert_eq!(
            verify_psk_inputs(HpkeMode::Psk, b"", b""),
            Err(CryptoError::BadInput)
        );
        assert_eq!(
            verify_psk_inputs(HpkeMode::Psk, b"psk", b""),
            Err(CryptoError::BadInput)
        );
        // Auth behaves like Base; AuthPSK behaves like PSK.
        assert!(verify_psk_inputs(HpkeMode::Auth, b"", b"").is_ok());
        assert!(verify_psk_inputs(HpkeMode::AuthPsk, b"psk", b"id").is_ok());
        assert_eq!(
            verify_psk_inputs(HpkeMode::AuthPsk, b"", b""),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn mode_ids() {
        assert_eq!(HpkeMode::Base.id(), 0x00);
        assert_eq!(HpkeMode::Psk.id(), 0x01);
        assert_eq!(HpkeMode::Auth.id(), 0x02);
        assert_eq!(HpkeMode::AuthPsk.id(), 0x03);
    }

    // Export-only AEAD: key/base_nonce empty, exporter_secret still derived.
    #[test]
    fn key_schedule_export_only_has_no_key() {
        let suite = hpke_suite_id(
            KemId::DhkemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::ExportOnly,
        );
        let shared_secret = [0x11u8; 32];
        let out = key_schedule(KeyScheduleParams {
            kdf: HpkeKdf::HkdfSha256,
            suite_id: &suite,
            mode: HpkeMode::Base,
            shared_secret: &shared_secret,
            info: b"",
            psk: b"",
            psk_id: b"",
            nk: 0,
            nn: 0,
        })
        .expect("key_schedule export-only");
        assert!(out.key.is_empty());
        assert!(out.base_nonce.is_empty());
        assert_eq!(out.exporter_secret.len(), 32);
    }
}
