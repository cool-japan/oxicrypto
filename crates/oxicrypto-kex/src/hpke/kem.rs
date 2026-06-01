//! DHKEM — the Diffie-Hellman-based Key Encapsulation Mechanism (RFC 9180 §4.1).
//!
//! Implements both KEMs required by this crate:
//!
//! * **DHKEM(X25519, HKDF-SHA256)** — `kem_id = 0x0020`, and
//! * **DHKEM(P-256, HKDF-SHA256)** — `kem_id = 0x0010`,
//!
//! each with `Encap`/`Decap` **and** the authenticated `AuthEncap`/`AuthDecap`
//! variants. Both KEMs use HKDF-SHA256 with the KEM `suite_id`, independent of
//! the key schedule's KDF.
//!
//! ## Reuse of the audited DH
//!
//! All Diffie-Hellman operations are delegated to the crate's
//! [`KeyAgreement::agree`] implementations ([`crate::X25519`], [`crate::EcdhP256`]),
//! which already reject all-zero / low-order shared secrets with
//! [`CryptoError::Kex`]. Only the two operations `agree()` cannot perform —
//! deriving a public key from a secret scalar, and **uncompressed** SEC1
//! serialization for P-256 — are implemented here against the dependency crates
//! directly.

use oxicrypto_core::{CryptoError, KeyAgreement, SecretVec};
use p256::elliptic_curve::sec1::ToSec1Point;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use super::ids::{i2osp, kem_suite_id, KemId};
use super::labeled::HpkeKdf;
use crate::{EcdhP256, X25519};

/// A DHKEM instance bound to a specific curve / KEM id (RFC 9180 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhKem {
    kem: KemId,
}

impl DhKem {
    /// Construct the DHKEM for the given [`KemId`].
    #[must_use]
    pub const fn new(kem: KemId) -> Self {
        Self { kem }
    }

    /// The KEM identifier of this instance.
    #[must_use]
    pub const fn kem_id(self) -> KemId {
        self.kem
    }

    /// Every DHKEM in this crate uses HKDF-SHA256 internally.
    #[inline]
    const fn kdf(self) -> HpkeKdf {
        HpkeKdf::HkdfSha256
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    /// `SerializePublicKey` — return the HPKE wire encoding of a public key.
    ///
    /// X25519 keys are the identity 32-byte encoding; P-256 keys are **always**
    /// serialized as uncompressed SEC1 (`0x04 ‖ x ‖ y`, 65 bytes). `pk` is the
    /// already-serialized public key in this crate's HPKE format, so this method
    /// merely validates its length / structure and returns a canonical copy.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if `pk` is not a valid serialized
    /// public key for this KEM.
    pub fn serialize_public_key(self, pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Deserialize-then-reserialize to obtain the canonical encoding and to
        // reject malformed inputs (e.g. compressed P-256 points).
        match self.kem {
            KemId::DhkemX25519HkdfSha256 => {
                if pk.len() != 32 {
                    return Err(CryptoError::InvalidKey);
                }
                Ok(pk.to_vec())
            }
            KemId::DhkemP256HkdfSha256 => {
                let canonical = p256_uncompressed_from_serialized(pk)?;
                Ok(canonical)
            }
        }
    }

    /// `DeserializePublicKey` — validate an HPKE-serialized public key.
    ///
    /// Returns the canonical serialized form (identical to the input for valid
    /// keys). For P-256 only uncompressed 65-byte encodings are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for malformed / wrong-length input.
    pub fn deserialize_public_key(self, enc: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.serialize_public_key(enc)
    }

    /// Derive the serialized public key from a raw secret scalar.
    ///
    /// This is the one operation `agree()` cannot perform. X25519 multiplies the
    /// (internally clamped) scalar by the base point; P-256 builds a `SecretKey`
    /// and serializes its public key uncompressed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if `sk` is not a valid scalar.
    pub fn public_key_from_secret(self, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self.kem {
            KemId::DhkemX25519HkdfSha256 => {
                let scalar: [u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
                // `x25519` clamps internally — exactly what HPKE expects.
                let pk = x25519(scalar, X25519_BASEPOINT_BYTES);
                Ok(pk.to_vec())
            }
            KemId::DhkemP256HkdfSha256 => {
                let fb: [u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
                let secret = p256::SecretKey::from_bytes(&p256::FieldBytes::from(fb))
                    .map_err(|_| CryptoError::InvalidKey)?;
                let pk = secret.public_key();
                Ok(pk.to_sec1_point(false).as_bytes().to_vec())
            }
        }
    }

    // ── Diffie-Hellman (delegated to the audited `agree`) ───────────────────────

    /// `DH(sk, pk)` — the curve scalar multiplication, returning the shared
    /// coordinate. Reuses [`KeyAgreement::agree`], inheriting its all-zero /
    /// low-order rejection.
    ///
    /// # Errors
    ///
    /// Propagates [`CryptoError`] from `agree()` (`InvalidKey`, `Kex`, …).
    fn dh(self, sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; 32];
        match self.kem {
            KemId::DhkemX25519HkdfSha256 => X25519.agree(sk, pk, &mut out)?,
            KemId::DhkemP256HkdfSha256 => EcdhP256.agree(sk, pk, &mut out)?,
        }
        Ok(out)
    }

    // ── DeriveKeyPair (RFC 9180 §7.1.3) ─────────────────────────────────────────

    /// `DeriveKeyPair(ikm)` — deterministically derive `(sk, serialized_pk)`
    /// from input keying material.
    ///
    /// X25519 expands a single 32-byte scalar; P-256 performs rejection sampling
    /// over a `candidate` counter until a valid scalar `0 < sk < n` is found.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Internal`] if P-256 rejection sampling is exhausted
    /// (probability ≈ `2^-256`), and propagates labeled-expand / key errors.
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<(SecretVec, Vec<u8>), CryptoError> {
        let suite = kem_suite_id(self.kem);
        let dkp_prk = self.kdf().labeled_extract(&suite, b"", b"dkp_prk", ikm);

        match self.kem {
            KemId::DhkemX25519HkdfSha256 => {
                let sk = self
                    .kdf()
                    .labeled_expand(&suite, &dkp_prk, b"sk", b"", 32)?;
                let pk = self.public_key_from_secret(&sk)?;
                Ok((SecretVec::new(sk), pk))
            }
            KemId::DhkemP256HkdfSha256 => {
                // Rejection sampling: counter 0..=255 (RFC 9180 §7.1.3).
                for counter in 0u16..=255 {
                    let mut bytes = self.kdf().labeled_expand(
                        &suite,
                        &dkp_prk,
                        b"candidate",
                        &i2osp(counter as u128, 1),
                        32,
                    )?;
                    // bitmask for P-256 is 0xff (no-op), kept for spec fidelity.
                    if let Some(first) = bytes.first_mut() {
                        *first &= 0xff;
                    }
                    // `from_bytes` is Ok iff 0 < scalar < group order — the exact
                    // acceptance predicate of DeriveKeyPair.
                    let fb: [u8; 32] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| CryptoError::InvalidKey)?;
                    if let Ok(secret) = p256::SecretKey::from_bytes(&p256::FieldBytes::from(fb)) {
                        let pk = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
                        return Ok((SecretVec::new(bytes), pk));
                    }
                }
                Err(CryptoError::Internal(
                    "HPKE DeriveKeyPair: rejection sampling exhausted",
                ))
            }
        }
    }

    // ── ExtractAndExpand (RFC 9180 §4.1) ────────────────────────────────────────

    /// `ExtractAndExpand(dh, kem_context)` — derive the `Nsecret`-byte KEM shared
    /// secret from the DH output and the KEM context.
    fn extract_and_expand(self, dh: &[u8], kem_context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let suite = kem_suite_id(self.kem);
        let eae_prk = self.kdf().labeled_extract(&suite, b"", b"eae_prk", dh);
        self.kdf().labeled_expand(
            &suite,
            &eae_prk,
            b"shared_secret",
            kem_context,
            self.kem.n_secret(),
        )
    }

    // ── Encap / Decap (RFC 9180 §4.1) ───────────────────────────────────────────

    /// `Encap(pkR)` derandomized to a fixed ephemeral `ikm_e` (KAT seam).
    ///
    /// Returns `(shared_secret, enc)` where `enc` is the serialized ephemeral
    /// public key.
    ///
    /// # Errors
    ///
    /// Propagates key / DH errors.
    pub(crate) fn encap_with_ikm(
        self,
        pk_r: &[u8],
        ikm_e: &[u8],
    ) -> Result<(SecretVec, Vec<u8>), CryptoError> {
        let pk_rm = self.deserialize_public_key(pk_r)?;
        let (sk_e, enc) = self.derive_key_pair(ikm_e)?;
        let dh = self.dh(sk_e.as_bytes(), &pk_rm)?;

        let mut kem_context = Vec::with_capacity(enc.len() + pk_rm.len());
        kem_context.extend_from_slice(&enc);
        kem_context.extend_from_slice(&pk_rm);

        let shared_secret = self.extract_and_expand(&dh, &kem_context)?;
        Ok((SecretVec::new(shared_secret), enc))
    }

    /// `Decap(enc, skR)` — recover the KEM shared secret at the recipient.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for a malformed `enc`, and propagates
    /// DH errors.
    pub fn decap(self, enc: &[u8], sk_r: &[u8]) -> Result<SecretVec, CryptoError> {
        let pk_e = self.deserialize_public_key(enc)?;
        let dh = self.dh(sk_r, &pk_e)?;
        let pk_rm = self.public_key_from_secret(sk_r)?;

        let mut kem_context = Vec::with_capacity(enc.len() + pk_rm.len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_rm);

        let shared_secret = self.extract_and_expand(&dh, &kem_context)?;
        Ok(SecretVec::new(shared_secret))
    }

    // ── AuthEncap / AuthDecap (RFC 9180 §4.1) ───────────────────────────────────

    /// `AuthEncap(pkR, skS)` derandomized to a fixed ephemeral `ikm_e`.
    ///
    /// Returns `(shared_secret, enc)`. The KEM context binds the sender's
    /// serialized public key for sender authentication.
    ///
    /// # Errors
    ///
    /// Propagates key / DH errors.
    pub(crate) fn auth_encap_with_ikm(
        self,
        pk_r: &[u8],
        sk_s: &[u8],
        ikm_e: &[u8],
    ) -> Result<(SecretVec, Vec<u8>), CryptoError> {
        let pk_rm = self.deserialize_public_key(pk_r)?;
        let (sk_e, enc) = self.derive_key_pair(ikm_e)?;

        // dh = DH(skE, pkR) ‖ DH(skS, pkR)
        let mut dh = self.dh(sk_e.as_bytes(), &pk_rm)?;
        let dh2 = self.dh(sk_s, &pk_rm)?;
        dh.extend_from_slice(&dh2);

        let pk_sm = self.public_key_from_secret(sk_s)?;
        let mut kem_context = Vec::with_capacity(enc.len() + pk_rm.len() + pk_sm.len());
        kem_context.extend_from_slice(&enc);
        kem_context.extend_from_slice(&pk_rm);
        kem_context.extend_from_slice(&pk_sm);

        let shared_secret = self.extract_and_expand(&dh, &kem_context)?;
        Ok((SecretVec::new(shared_secret), enc))
    }

    /// `AuthDecap(enc, skR, pkS)` — recover the shared secret and authenticate
    /// the sender's static key `pkS`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for malformed `enc` / `pkS`, and
    /// propagates DH errors.
    pub fn auth_decap(
        self,
        enc: &[u8],
        sk_r: &[u8],
        pk_s: &[u8],
    ) -> Result<SecretVec, CryptoError> {
        let pk_e = self.deserialize_public_key(enc)?;
        let pk_sm = self.deserialize_public_key(pk_s)?;

        // dh = DH(skR, pkE) ‖ DH(skR, pkS)
        let mut dh = self.dh(sk_r, &pk_e)?;
        let dh2 = self.dh(sk_r, &pk_sm)?;
        dh.extend_from_slice(&dh2);

        let pk_rm = self.public_key_from_secret(sk_r)?;
        let mut kem_context = Vec::with_capacity(enc.len() + pk_rm.len() + pk_sm.len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_rm);
        kem_context.extend_from_slice(&pk_sm);

        let shared_secret = self.extract_and_expand(&dh, &kem_context)?;
        Ok(SecretVec::new(shared_secret))
    }
}

/// Validate a serialized P-256 public key and return its canonical uncompressed
/// (65-byte) SEC1 encoding.
///
/// Only uncompressed encodings (length 65, `0x04` prefix) are accepted for HPKE;
/// compressed (33-byte) or otherwise-malformed inputs are rejected.
fn p256_uncompressed_from_serialized(enc: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if enc.len() != 65 || enc.first() != Some(&0x04) {
        return Err(CryptoError::InvalidKey);
    }
    // `from_sec1_bytes` enforces that the point is actually on the curve.
    let pk = p256::PublicKey::from_sec1_bytes(enc).map_err(|_| CryptoError::InvalidKey)?;
    Ok(pk.to_sec1_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod kem_tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex in test vector")
    }

    // RFC 9180 A.1.1 — DeriveKeyPair for X25519 must reproduce the vector keys.
    #[test]
    fn derive_key_pair_x25519_a_1_1() {
        let kem = DhKem::new(KemId::DhkemX25519HkdfSha256);
        let ikm_e = hx("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let sk_em = hx("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let pk_em = hx("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let (sk, pk) = kem.derive_key_pair(&ikm_e).expect("derive eph");
        assert_eq!(sk.as_bytes(), sk_em.as_slice(), "X25519 skEm mismatch");
        assert_eq!(pk, pk_em, "X25519 pkEm mismatch");

        let ikm_r = hx("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
        let sk_rm = hx("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let pk_rm = hx("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let (skr, pkr) = kem.derive_key_pair(&ikm_r).expect("derive recip");
        assert_eq!(skr.as_bytes(), sk_rm.as_slice(), "X25519 skRm mismatch");
        assert_eq!(pkr, pk_rm, "X25519 pkRm mismatch");
    }

    // RFC 9180 A.3.1 — DeriveKeyPair for P-256 (exercises rejection sampling and
    // the 65-byte uncompressed encoding).
    #[test]
    fn derive_key_pair_p256_a_3_1() {
        let kem = DhKem::new(KemId::DhkemP256HkdfSha256);
        let ikm_e = hx("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e");
        let sk_em = hx("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb");
        let pk_em = hx("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
        let (sk, pk) = kem.derive_key_pair(&ikm_e).expect("derive eph");
        assert_eq!(sk.as_bytes(), sk_em.as_slice(), "P-256 skEm mismatch");
        assert_eq!(pk.len(), 65, "P-256 pk must be uncompressed (65 bytes)");
        assert_eq!(pk.first(), Some(&0x04));
        assert_eq!(pk, pk_em, "P-256 pkEm mismatch");

        let ikm_r = hx("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550");
        let sk_rm = hx("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        let pk_rm = hx("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
        let (skr, pkr) = kem.derive_key_pair(&ikm_r).expect("derive recip");
        assert_eq!(skr.as_bytes(), sk_rm.as_slice(), "P-256 skRm mismatch");
        assert_eq!(pkr, pk_rm, "P-256 pkRm mismatch");
    }

    // RFC 9180 A.1.1 — Encap(pkR) derandomized must reproduce enc + shared_secret.
    #[test]
    fn encap_x25519_a_1_1() {
        let kem = DhKem::new(KemId::DhkemX25519HkdfSha256);
        let ikm_e = hx("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let pk_rm = hx("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let enc_expected = hx("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let ss_expected = hx("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");

        let (ss, enc) = kem.encap_with_ikm(&pk_rm, &ikm_e).expect("encap");
        assert_eq!(enc, enc_expected, "enc mismatch");
        assert_eq!(
            ss.as_bytes(),
            ss_expected.as_slice(),
            "shared_secret mismatch"
        );

        // Decap must recover the same shared secret.
        let sk_rm = hx("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let ss_dec = kem.decap(&enc, &sk_rm).expect("decap");
        assert_eq!(ss_dec.as_bytes(), ss_expected.as_slice());
    }

    // RFC 9180 A.3.1 — Encap(pkR) derandomized for P-256.
    #[test]
    fn encap_p256_a_3_1() {
        let kem = DhKem::new(KemId::DhkemP256HkdfSha256);
        let ikm_e = hx("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e");
        let pk_rm = hx("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
        let enc_expected = hx("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
        let ss_expected = hx("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");

        let (ss, enc) = kem.encap_with_ikm(&pk_rm, &ikm_e).expect("encap");
        assert_eq!(enc, enc_expected, "P-256 enc mismatch");
        assert_eq!(
            ss.as_bytes(),
            ss_expected.as_slice(),
            "P-256 shared_secret mismatch"
        );

        let sk_rm = hx("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        let ss_dec = kem.decap(&enc, &sk_rm).expect("decap");
        assert_eq!(ss_dec.as_bytes(), ss_expected.as_slice());
    }

    // P-256 deserialization must reject a compressed (33-byte) encoding.
    #[test]
    fn p256_rejects_compressed_enc() {
        let kem = DhKem::new(KemId::DhkemP256HkdfSha256);
        // Compressed form of the A.3.1 pkRm (0x02/0x03 prefix + x): build it.
        let pk_rm = hx("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
        let compressed = p256::PublicKey::from_sec1_bytes(&pk_rm)
            .expect("valid")
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        assert_eq!(compressed.len(), 33);
        assert_eq!(
            kem.deserialize_public_key(&compressed),
            Err(CryptoError::InvalidKey)
        );
        // Truncated input is also rejected.
        assert_eq!(
            kem.deserialize_public_key(&pk_rm[..64]),
            Err(CryptoError::InvalidKey)
        );
    }

    // AuthEncap/AuthDecap must agree (round-trip) for both curves.
    #[test]
    fn auth_round_trip_x25519() {
        let kem = DhKem::new(KemId::DhkemX25519HkdfSha256);
        let ikm_e = hx("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let (sk_r, pk_r) = kem
            .derive_key_pair(&hx(
                "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
            ))
            .expect("recip");
        let (sk_s, pk_s) = kem
            .derive_key_pair(&hx(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ))
            .expect("sender");

        let (ss_enc, enc) = kem
            .auth_encap_with_ikm(&pk_r, sk_s.as_bytes(), &ikm_e)
            .expect("auth_encap");
        let ss_dec = kem
            .auth_decap(&enc, sk_r.as_bytes(), &pk_s)
            .expect("auth_decap");
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn auth_round_trip_p256() {
        let kem = DhKem::new(KemId::DhkemP256HkdfSha256);
        let ikm_e = hx("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e");
        let (sk_r, pk_r) = kem
            .derive_key_pair(&hx(
                "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550",
            ))
            .expect("recip");
        let (sk_s, pk_s) = kem
            .derive_key_pair(&hx(
                "2222222222222222222222222222222222222222222222222222222222222222",
            ))
            .expect("sender");

        let (ss_enc, enc) = kem
            .auth_encap_with_ikm(&pk_r, sk_s.as_bytes(), &ikm_e)
            .expect("auth_encap");
        let ss_dec = kem
            .auth_decap(&enc, sk_r.as_bytes(), &pk_s)
            .expect("auth_decap");
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }
}
