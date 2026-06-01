//! [`HpkeSuite`] — the public HPKE API (RFC 9180 §5–§6).
//!
//! An `HpkeSuite` bundles a KEM, KDF, and AEAD and exposes:
//!
//! * key management — [`derive_key_pair`](HpkeSuite::derive_key_pair),
//!   [`generate_key_pair`](HpkeSuite::generate_key_pair);
//! * length accessors — `n_enc`, `n_pk`, `n_sk`, `n_k`, `n_n`, `n_t`;
//! * setup for every mode — `setup_{base,psk,auth,auth_psk}_{s,r}`; and
//! * single-shot [`seal_base`](HpkeSuite::seal_base) / [`open_base`](HpkeSuite::open_base).
//!
//! Sender setup draws a random ephemeral key from an RNG; the `pub(crate)`
//! `*_deterministic` variants take an explicit `ikm_e`, used only by the
//! in-crate known-answer tests.

use oxicrypto_core::{CryptoError, SecretVec};

use super::context::{ContextConfig, HpkeAead, HpkeContextR, HpkeContextS};
use super::ids::{hpke_suite_id, AeadId, KdfId, KemId};
use super::kem::DhKem;
use super::key_schedule::{key_schedule, HpkeMode, KeyScheduleParams};
use super::labeled::HpkeKdf;

/// A complete HPKE ciphersuite: KEM × KDF × AEAD (RFC 9180 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeSuite {
    kem: KemId,
    kdf: KdfId,
    aead: AeadId,
}

impl HpkeSuite {
    /// Construct a suite from its three algorithm identifiers.
    #[must_use]
    pub const fn new(kem: KemId, kdf: KdfId, aead: AeadId) -> Self {
        Self { kem, kdf, aead }
    }

    /// The KEM identifier.
    #[must_use]
    pub const fn kem(self) -> KemId {
        self.kem
    }

    /// The KDF identifier.
    #[must_use]
    pub const fn kdf(self) -> KdfId {
        self.kdf
    }

    /// The AEAD identifier.
    #[must_use]
    pub const fn aead(self) -> AeadId {
        self.aead
    }

    /// `Nenc` — encapsulated-key length in bytes.
    #[must_use]
    pub const fn n_enc(self) -> usize {
        self.kem.n_enc()
    }

    /// `Npk` — serialized public-key length in bytes.
    #[must_use]
    pub const fn n_pk(self) -> usize {
        self.kem.n_pk()
    }

    /// `Nsk` — serialized private-key length in bytes.
    #[must_use]
    pub const fn n_sk(self) -> usize {
        self.kem.n_sk()
    }

    /// `Nk` — AEAD key length in bytes.
    #[must_use]
    pub const fn n_k(self) -> usize {
        self.aead.n_k()
    }

    /// `Nn` — AEAD nonce length in bytes.
    #[must_use]
    pub const fn n_n(self) -> usize {
        self.aead.n_n()
    }

    /// `Nt` — AEAD tag length in bytes.
    #[must_use]
    pub const fn n_t(self) -> usize {
        self.aead.n_t()
    }

    // ── Internal helpers ────────────────────────────────────────────────────────

    #[inline]
    const fn dhkem(self) -> DhKem {
        DhKem::new(self.kem)
    }

    #[inline]
    const fn hpke_kdf(self) -> HpkeKdf {
        match self.kdf {
            KdfId::HkdfSha256 => HpkeKdf::HkdfSha256,
            KdfId::HkdfSha384 => HpkeKdf::HkdfSha384,
            KdfId::HkdfSha512 => HpkeKdf::HkdfSha512,
        }
    }

    #[inline]
    fn suite_id(self) -> Vec<u8> {
        hpke_suite_id(self.kem, self.kdf, self.aead)
    }

    /// Run the key schedule and assemble the shared [`ContextConfig`].
    fn derive_context_config(
        self,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        mode: HpkeMode,
    ) -> Result<ContextConfig, CryptoError> {
        let suite_id = self.suite_id();
        let ks = key_schedule(KeyScheduleParams {
            kdf: self.hpke_kdf(),
            suite_id: &suite_id,
            mode,
            shared_secret,
            info,
            psk,
            psk_id,
            nk: self.n_k(),
            nn: self.n_n(),
        })?;
        Ok(ContextConfig {
            aead: HpkeAead::from_id(self.aead),
            kdf: self.hpke_kdf(),
            suite_id,
            key: ks.key,
            base_nonce: ks.base_nonce,
            exporter_secret: ks.exporter_secret,
            nn: self.n_n(),
            nt: self.n_t(),
        })
    }

    /// Build a sender context from a freshly computed shared secret.
    fn build_context_s(
        self,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        mode: HpkeMode,
    ) -> Result<HpkeContextS, CryptoError> {
        let config = self.derive_context_config(shared_secret, info, psk, psk_id, mode)?;
        Ok(HpkeContextS::new(config))
    }

    /// Build a recipient context from a freshly computed shared secret.
    fn build_context_r(
        self,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        mode: HpkeMode,
    ) -> Result<HpkeContextR, CryptoError> {
        let config = self.derive_context_config(shared_secret, info, psk, psk_id, mode)?;
        Ok(HpkeContextR::new(config))
    }

    // ── Key management ──────────────────────────────────────────────────────────

    /// `DeriveKeyPair(ikm)` — deterministically derive `(sk, serialized_pk)`.
    ///
    /// # Errors
    ///
    /// Propagates KEM errors (e.g. P-256 rejection-sampling exhaustion).
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<(SecretVec, Vec<u8>), CryptoError> {
        self.dhkem().derive_key_pair(ikm)
    }

    /// `GenerateKeyPair()` — draw `Nsk` random bytes and derive a key pair.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] on RNG failure; propagates KEM errors.
    pub fn generate_key_pair<R>(self, rng: &mut R) -> Result<(SecretVec, Vec<u8>), CryptoError>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut ikm = vec![0u8; self.n_sk()];
        rng.try_fill_bytes(&mut ikm).map_err(|_| CryptoError::Rng)?;
        self.derive_key_pair(&ikm)
    }

    /// `SerializePublicKey` — canonical HPKE encoding of a public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for malformed input.
    pub fn serialize_public_key(self, pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.dhkem().serialize_public_key(pk)
    }

    /// `Serialize`-validate an encapsulated/serialized public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for malformed input.
    pub fn deserialize_public_key(self, enc: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.dhkem().deserialize_public_key(enc)
    }

    // ── Mode: Base ──────────────────────────────────────────────────────────────

    /// `SetupBaseS()` derandomized to an explicit `ikm_e` (KAT seam).
    ///
    /// # Errors
    ///
    /// Propagates KEM / key-schedule errors.
    pub(crate) fn setup_base_s_deterministic(
        self,
        pk_r: &[u8],
        info: &[u8],
        ikm_e: &[u8],
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError> {
        let (shared_secret, enc) = self.dhkem().encap_with_ikm(pk_r, ikm_e)?;
        let ctx = self.build_context_s(shared_secret.as_bytes(), info, b"", b"", HpkeMode::Base)?;
        Ok((enc, ctx))
    }

    /// `SetupBaseS()` — sender setup for mode Base (RFC 9180 §5.1.1).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] on RNG failure; propagates KEM errors.
    pub fn setup_base_s<R>(
        self,
        pk_r: &[u8],
        info: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut ikm_e = vec![0u8; self.n_sk()];
        rng.try_fill_bytes(&mut ikm_e)
            .map_err(|_| CryptoError::Rng)?;
        self.setup_base_s_deterministic(pk_r, info, &ikm_e)
    }

    /// `SetupBaseR()` — recipient setup for mode Base.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for malformed `enc`; propagates KEM /
    /// key-schedule errors.
    pub fn setup_base_r(
        self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
    ) -> Result<HpkeContextR, CryptoError> {
        let shared_secret = self.dhkem().decap(enc, sk_r)?;
        self.build_context_r(shared_secret.as_bytes(), info, b"", b"", HpkeMode::Base)
    }

    // ── Mode: PSK ───────────────────────────────────────────────────────────────

    /// `SetupPSKS()` derandomized to an explicit `ikm_e`.
    ///
    /// # Errors
    ///
    /// Propagates KEM / key-schedule errors (including PSK-input validation).
    pub(crate) fn setup_psk_s_deterministic(
        self,
        pk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        ikm_e: &[u8],
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError> {
        let (shared_secret, enc) = self.dhkem().encap_with_ikm(pk_r, ikm_e)?;
        let ctx =
            self.build_context_s(shared_secret.as_bytes(), info, psk, psk_id, HpkeMode::Psk)?;
        Ok((enc, ctx))
    }

    /// `SetupPSKS()` — sender setup for mode PSK (RFC 9180 §5.1.2).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] on RNG failure, [`CryptoError::BadInput`] for
    /// invalid PSK inputs; propagates KEM errors.
    pub fn setup_psk_s<R>(
        self,
        pk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut ikm_e = vec![0u8; self.n_sk()];
        rng.try_fill_bytes(&mut ikm_e)
            .map_err(|_| CryptoError::Rng)?;
        self.setup_psk_s_deterministic(pk_r, info, psk, psk_id, &ikm_e)
    }

    /// `SetupPSKR()` — recipient setup for mode PSK.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] / [`CryptoError::BadInput`]; propagates
    /// KEM / key-schedule errors.
    pub fn setup_psk_r(
        self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeContextR, CryptoError> {
        let shared_secret = self.dhkem().decap(enc, sk_r)?;
        self.build_context_r(shared_secret.as_bytes(), info, psk, psk_id, HpkeMode::Psk)
    }

    // ── Mode: Auth ──────────────────────────────────────────────────────────────

    /// `SetupAuthS()` derandomized to an explicit `ikm_e`.
    ///
    /// # Errors
    ///
    /// Propagates KEM / key-schedule errors.
    pub(crate) fn setup_auth_s_deterministic(
        self,
        pk_r: &[u8],
        info: &[u8],
        sk_s: &[u8],
        ikm_e: &[u8],
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError> {
        let (shared_secret, enc) = self.dhkem().auth_encap_with_ikm(pk_r, sk_s, ikm_e)?;
        let ctx = self.build_context_s(shared_secret.as_bytes(), info, b"", b"", HpkeMode::Auth)?;
        Ok((enc, ctx))
    }

    /// `SetupAuthS()` — sender setup for mode Auth (RFC 9180 §5.1.3).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] on RNG failure; propagates KEM errors.
    pub fn setup_auth_s<R>(
        self,
        pk_r: &[u8],
        info: &[u8],
        sk_s: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut ikm_e = vec![0u8; self.n_sk()];
        rng.try_fill_bytes(&mut ikm_e)
            .map_err(|_| CryptoError::Rng)?;
        self.setup_auth_s_deterministic(pk_r, info, sk_s, &ikm_e)
    }

    /// `SetupAuthR()` — recipient setup for mode Auth, authenticating `pk_s`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`]; propagates KEM / key-schedule errors.
    pub fn setup_auth_r(
        self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        pk_s: &[u8],
    ) -> Result<HpkeContextR, CryptoError> {
        let shared_secret = self.dhkem().auth_decap(enc, sk_r, pk_s)?;
        self.build_context_r(shared_secret.as_bytes(), info, b"", b"", HpkeMode::Auth)
    }

    // ── Mode: AuthPSK ───────────────────────────────────────────────────────────

    /// `SetupAuthPSKS()` derandomized to an explicit `ikm_e`.
    ///
    /// # Errors
    ///
    /// Propagates KEM / key-schedule errors (including PSK-input validation).
    pub(crate) fn setup_auth_psk_s_deterministic(
        self,
        pk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sk_s: &[u8],
        ikm_e: &[u8],
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError> {
        let (shared_secret, enc) = self.dhkem().auth_encap_with_ikm(pk_r, sk_s, ikm_e)?;
        let ctx = self.build_context_s(
            shared_secret.as_bytes(),
            info,
            psk,
            psk_id,
            HpkeMode::AuthPsk,
        )?;
        Ok((enc, ctx))
    }

    /// `SetupAuthPSKS()` — sender setup for mode AuthPSK (RFC 9180 §5.1.4).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] / [`CryptoError::BadInput`]; propagates KEM
    /// errors.
    pub fn setup_auth_psk_s<R>(
        self,
        pk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sk_s: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContextS), CryptoError>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut ikm_e = vec![0u8; self.n_sk()];
        rng.try_fill_bytes(&mut ikm_e)
            .map_err(|_| CryptoError::Rng)?;
        self.setup_auth_psk_s_deterministic(pk_r, info, psk, psk_id, sk_s, &ikm_e)
    }

    /// `SetupAuthPSKR()` — recipient setup for mode AuthPSK.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] / [`CryptoError::BadInput`]; propagates
    /// KEM / key-schedule errors.
    pub fn setup_auth_psk_r(
        self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pk_s: &[u8],
    ) -> Result<HpkeContextR, CryptoError> {
        let shared_secret = self.dhkem().auth_decap(enc, sk_r, pk_s)?;
        self.build_context_r(
            shared_secret.as_bytes(),
            info,
            psk,
            psk_id,
            HpkeMode::AuthPsk,
        )
    }

    // ── Single-shot (RFC 9180 §6.1) ─────────────────────────────────────────────

    /// `SealBase(pkR, info, aad, pt)` — one-shot encryption for mode Base.
    ///
    /// Returns `(enc, ciphertext)`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] on RNG failure,
    /// [`CryptoError::UnsupportedAlgorithm`] for an export-only suite; propagates
    /// KEM / AEAD errors.
    pub fn seal_base<R>(
        self,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let (enc, mut ctx) = self.setup_base_s(pk_r, info, rng)?;
        let ct = ctx.seal(aad, pt)?;
        Ok((enc, ct))
    }

    /// `OpenBase(enc, skR, info, aad, ct)` — one-shot decryption for mode Base.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] / [`CryptoError::InvalidTag`] /
    /// [`CryptoError::UnsupportedAlgorithm`]; propagates KEM / AEAD errors.
    pub fn open_base(
        self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut ctx = self.setup_base_r(enc, sk_r, info)?;
        ctx.open(aad, ct)
    }
}
