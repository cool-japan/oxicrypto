//! Hybrid KEM constructions for post-quantum + classical security.
//!
//! # Constructions
//!
//! | Type | PQ | Classical | Combiner |
//! |------|----|-----------|---------|
//! | [`XWing768`] | ML-KEM-768 | X25519 | SHA3-256 per draft-connolly-cfrg-xwing-kem-04 |
//! | [`HybridKem1024P384`] | ML-KEM-1024 | ECDH P-384 | HKDF-SHA-384 (ounsworth-style) |
//!
//! # Security note
//!
//! The X25519 sub-operation rejects all-zero DH output (low-order point
//! protection) per the kex crate's `agree()` implementation.  The X-Wing
//! draft does not require this check, but it is still safe.

use oxicrypto_core::KeyAgreement;
use oxicrypto_core::{CryptoError, Kem, SecretKey, SecretVec};
use oxicrypto_kex::{ecdh_p384_generate_keypair, x25519_generate_keypair, EcdhP384, X25519};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::mlkem::{
    Ciphertext1024, Ciphertext768, DecapKey1024, DecapKey768, EncapKey1024, EncapKey768, MlKem1024,
    MlKem768,
};

// ─────────────────────────────────────────────────────────────────────────────
//  OS-seeded RNG helper
// ─────────────────────────────────────────────────────────────────────────────

fn hybrid_os_rng() -> Result<rand_chacha::ChaCha20Rng, CryptoError> {
    use rand_core::SeedableRng;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
    Ok(rand_chacha::ChaCha20Rng::from_seed(seed))
}

// ─────────────────────────────────────────────────────────────────────────────
//  X-Wing constants
//
//  draft-connolly-cfrg-xwing-kem-04, Section 4:
//
//    XWingLabel = ASCII string "\.//^\\"
//    Bytes: 0x5c 0x2e 0x2f 0x2f 0x5e 0x5c  (6 bytes)
//
//  Note: The draft uses \.//^\\ which in Rust string literal form is
//  b"\\.//^\\" — the double backslash in the Rust source produces the single
//  backslash byte.  Verify: XWING_LABEL.len() == 6.
// ─────────────────────────────────────────────────────────────────────────────

/// X-Wing combiner label: 6-byte ASCII `\.//^\\`
/// (draft-connolly-cfrg-xwing-kem-04 §4, hex: `5c 2e 2f 2f 5e 5c`).
///
/// Verified against Appendix C KAT vector #1 — the combiner produces the
/// correct shared secret `555a071a8b7520ae95f8e635de8a5f87dbddcbef900576aad29ecdda5459c15a`.
const XWING_LABEL: &[u8] = b"\\.//^\\";

/// Combiner: `SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)`.
fn xwing_combine(ss_m: &[u8; 32], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(XWING_LABEL);
    h.update(ss_m);
    h.update(ss_x);
    h.update(ct_x);
    h.update(pk_x);
    h.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
//  X-Wing types
// ─────────────────────────────────────────────────────────────────────────────

/// Combined encapsulation (public) key for X-Wing (ML-KEM-768 + X25519).
#[derive(Clone)]
pub struct XWing768EncapKey {
    /// ML-KEM-768 encapsulation key.
    pub mlkem_ek: EncapKey768,
    /// Recipient's static X25519 public key (32 bytes).
    pub x25519_pk: [u8; 32],
}

/// Combined decapsulation (private) key for X-Wing.
///
/// The inner `SecretKey<32>` is zeroized on drop.
pub struct XWing768DecapKey {
    /// ML-KEM-768 decapsulation key.
    pub mlkem_dk: DecapKey768,
    /// X25519 static secret key (zeroizes on drop).
    pub x25519_sk: SecretKey<32>,
    /// X25519 static public key (needed in the decap combiner).
    pub x25519_pk: [u8; 32],
}

/// Ciphertext produced by [`XWing768::kem_encapsulate`].
#[derive(Clone)]
pub struct XWing768Ciphertext {
    /// ML-KEM-768 ciphertext.
    pub mlkem_ct: Ciphertext768,
    /// Ephemeral X25519 public key (32 bytes).
    pub x25519_ct: [u8; 32],
}

/// 32-byte shared secret from X-Wing encapsulation / decapsulation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct XWingSharedSecret(pub(crate) [u8; 32]);

impl XWingSharedSecret {
    /// Borrow the raw 32 secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for XWingSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for XWingSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "XWingSharedSecret(***)")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  X-Wing: Kem impl
// ─────────────────────────────────────────────────────────────────────────────

/// X-Wing hybrid KEM: ML-KEM-768 + X25519 per draft-connolly-cfrg-xwing-kem-04.
pub struct XWing768;

impl Kem for XWing768 {
    type DecapKey = XWing768DecapKey;
    type EncapKey = XWing768EncapKey;
    type Ciphertext = XWing768Ciphertext;
    type SharedSecret = XWingSharedSecret;

    fn kem_generate() -> Result<(Self::DecapKey, Self::EncapKey), CryptoError> {
        let mut rng = hybrid_os_rng()?;
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut rng);
        let (x25519_sk, x25519_pk) = x25519_generate_keypair(&mut rng)?;
        let dk = XWing768DecapKey {
            mlkem_dk,
            x25519_sk,
            x25519_pk,
        };
        let ek = XWing768EncapKey {
            mlkem_ek,
            x25519_pk,
        };
        Ok((dk, ek))
    }

    fn kem_encapsulate(
        ek: &Self::EncapKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError> {
        let mut rng = hybrid_os_rng()?;

        // ML-KEM-768 encapsulate.
        let (mlkem_ct, ss_m_key) = ek.mlkem_ek.encapsulate(&mut rng)?;

        // Ephemeral X25519 keypair for the DH component.
        let (eph_sk, eph_pk) = x25519_generate_keypair(&mut rng)?;

        // X25519 DH: ss_X = DH(eph_sk, recipient_pk).
        let mut ss_x = [0u8; 32];
        X25519.agree(eph_sk.as_bytes(), &ek.x25519_pk, &mut ss_x)?;

        // X25519 ciphertext = ephemeral public key (the "c_X" in the draft).
        let ct_x = eph_pk;

        // ss_M as fixed array.
        let ss_m_arr: [u8; 32] = ss_m_key
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Internal("ss_m length mismatch"))?;

        // SHA3-256 combiner.
        let ss_raw = xwing_combine(&ss_m_arr, &ss_x, &ct_x, &ek.x25519_pk);

        let ct = XWing768Ciphertext {
            mlkem_ct,
            x25519_ct: ct_x,
        };
        Ok((ct, XWingSharedSecret(ss_raw)))
    }

    fn kem_decapsulate(
        dk: &Self::DecapKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError> {
        // ML-KEM-768 decapsulate.
        let ss_m_key = dk.mlkem_dk.decapsulate(&ct.mlkem_ct)?;

        // X25519 DH: ss_X = DH(static_sk, ephemeral_pk in ct).
        let mut ss_x = [0u8; 32];
        X25519.agree(dk.x25519_sk.as_bytes(), &ct.x25519_ct, &mut ss_x)?;

        let ss_m_arr: [u8; 32] = ss_m_key
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Internal("ss_m length mismatch"))?;

        // Combiner uses the recipient's static pk (stored in dk).
        let ss_raw = xwing_combine(&ss_m_arr, &ss_x, &ct.x25519_ct, &dk.x25519_pk);
        Ok(XWingSharedSecret(ss_raw))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hybrid ML-KEM-1024 + ECDH P-384 constants
// ─────────────────────────────────────────────────────────────────────────────

/// HKDF-SHA-384 salt for the Hybrid ML-KEM-1024 + P-384 combiner.
const HYBRID_LABEL: &[u8; 32] = b"oxicrypto-hybrid-mlkem1024-p384\x00";

// ─────────────────────────────────────────────────────────────────────────────
//  Hybrid ML-KEM-1024 + P-384 types
// ─────────────────────────────────────────────────────────────────────────────

/// Combined encapsulation (public) key for Hybrid ML-KEM-1024 + ECDH P-384.
#[derive(Clone)]
pub struct HybridKem1024P384EncapKey {
    /// ML-KEM-1024 encapsulation key.
    pub mlkem_ek: EncapKey1024,
    /// P-384 public key (SEC1 compressed, 49 bytes).
    pub p384_pk: Vec<u8>,
}

/// Combined decapsulation (private) key for Hybrid ML-KEM-1024 + ECDH P-384.
pub struct HybridKem1024P384DecapKey {
    /// ML-KEM-1024 decapsulation key.
    pub mlkem_dk: DecapKey1024,
    /// P-384 private scalar (48 bytes, zeroizes on drop).
    pub p384_sk: SecretVec,
    /// P-384 public key (SEC1 compressed, 49 bytes).
    pub p384_pk: Vec<u8>,
    /// Serialized ML-KEM-1024 encapsulation key (1568 bytes).
    ///
    /// Stored to allow the decapsulator to reconstruct the combiner input
    /// `ek_M` without access to the encapsulation key.
    pub mlkem_ek_bytes: Vec<u8>,
}

/// Ciphertext produced by [`HybridKem1024P384::kem_encapsulate`].
#[derive(Clone)]
pub struct HybridKem1024P384Ciphertext {
    /// ML-KEM-1024 ciphertext.
    pub mlkem_ct: Ciphertext1024,
    /// Ephemeral P-384 public key (SEC1 compressed, 49 bytes).
    pub p384_ct: Vec<u8>,
}

/// 32-byte shared secret from Hybrid ML-KEM-1024 + P-384.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridP384SharedSecret(pub(crate) [u8; 32]);

impl HybridP384SharedSecret {
    /// Borrow the raw 32 secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for HybridP384SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for HybridP384SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HybridP384SharedSecret(***)")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hybrid combiner
// ─────────────────────────────────────────────────────────────────────────────

/// Combine all KEM inputs via HKDF-SHA-384 into a 32-byte shared secret.
///
/// `IKM = ss_m || ss_e || ct_m || ct_e || ek_m || ek_e`
fn hybrid_p384_combine(
    ss_m: &[u8],
    ss_e: &[u8],
    ct_m: &[u8],
    ct_e: &[u8],
    ek_m: &[u8],
    ek_e: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let cap = ss_m.len() + ss_e.len() + ct_m.len() + ct_e.len() + ek_m.len() + ek_e.len();
    let mut ikm = Vec::with_capacity(cap);
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(ss_e);
    ikm.extend_from_slice(ct_m);
    ikm.extend_from_slice(ct_e);
    ikm.extend_from_slice(ek_m);
    ikm.extend_from_slice(ek_e);

    let prk = oxicrypto_kdf::hkdf_sha384_extract(HYBRID_LABEL, &ikm);
    let mut out = [0u8; 32];
    oxicrypto_kdf::hkdf_sha384_expand(&prk, b"oxicrypto-hybrid-mlkem1024-p384", &mut out)?;
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hybrid ML-KEM-1024 + P-384: Kem impl
// ─────────────────────────────────────────────────────────────────────────────

/// Hybrid KEM: ML-KEM-1024 + ECDH P-384 (CNSA 2.0 target).
///
/// The shared secret is derived via HKDF-SHA-384 over all components for
/// transcript binding (ss_M, ss_E, ML-KEM ciphertext, ephemeral P-384 pk,
/// recipient ML-KEM ek, recipient P-384 pk).
pub struct HybridKem1024P384;

impl Kem for HybridKem1024P384 {
    type DecapKey = HybridKem1024P384DecapKey;
    type EncapKey = HybridKem1024P384EncapKey;
    type Ciphertext = HybridKem1024P384Ciphertext;
    type SharedSecret = HybridP384SharedSecret;

    fn kem_generate() -> Result<(Self::DecapKey, Self::EncapKey), CryptoError> {
        let mut rng = hybrid_os_rng()?;
        let (mlkem_dk, mlkem_ek) = MlKem1024::generate(&mut rng);

        // Serialize the encap key for storage in the decap key (needed in decap combiner).
        let mlkem_ek_bytes = mlkem_ek.to_bytes();

        let (p384_sk, p384_pk) = ecdh_p384_generate_keypair(&mut rng)?;
        let dk = HybridKem1024P384DecapKey {
            mlkem_dk,
            p384_sk,
            p384_pk: p384_pk.clone(),
            mlkem_ek_bytes,
        };
        let ek = HybridKem1024P384EncapKey { mlkem_ek, p384_pk };
        Ok((dk, ek))
    }

    fn kem_encapsulate(
        ek: &Self::EncapKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError> {
        let mut rng = hybrid_os_rng()?;

        // ML-KEM-1024 encapsulate.
        let (mlkem_ct, ss_m_key) = ek.mlkem_ek.encapsulate(&mut rng)?;

        // Ephemeral P-384 keypair.
        let (eph_p384_sk, eph_p384_pk) = ecdh_p384_generate_keypair(&mut rng)?;

        // P-384 ECDH: ss_e = DH(eph_sk, recipient_pk) → 48-byte x-coord.
        let mut ss_e = [0u8; 48];
        EcdhP384.agree(eph_p384_sk.as_bytes(), &ek.p384_pk, &mut ss_e)?;

        // Serialize inputs for the combiner.
        let ct_m_bytes = mlkem_ct.to_bytes();
        let ct_e_bytes = eph_p384_pk; // 49-byte SEC1 compressed ephemeral pk
        let ek_m_bytes = ek.mlkem_ek.to_bytes();
        let ek_e_bytes = &ek.p384_pk;

        // Combiner.
        let ss_raw = hybrid_p384_combine(
            ss_m_key.as_ref(),
            &ss_e,
            &ct_m_bytes,
            &ct_e_bytes,
            &ek_m_bytes,
            ek_e_bytes,
        )?;

        let ct = HybridKem1024P384Ciphertext {
            mlkem_ct,
            p384_ct: ct_e_bytes,
        };
        Ok((ct, HybridP384SharedSecret(ss_raw)))
    }

    fn kem_decapsulate(
        dk: &Self::DecapKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError> {
        // ML-KEM-1024 decapsulate.
        let ss_m_key = dk.mlkem_dk.decapsulate(&ct.mlkem_ct)?;

        // P-384 ECDH.
        let mut ss_e = [0u8; 48];
        EcdhP384.agree(dk.p384_sk.as_bytes(), &ct.p384_ct, &mut ss_e)?;

        // Reconstruct combiner inputs using stored ek_m bytes.
        let ct_m_bytes = ct.mlkem_ct.to_bytes();

        let ss_raw = hybrid_p384_combine(
            ss_m_key.as_ref(),
            &ss_e,
            &ct_m_bytes,
            &ct.p384_ct,
            &dk.mlkem_ek_bytes,
            &dk.p384_pk,
        )?;

        Ok(HybridP384SharedSecret(ss_raw))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  PqKeyShare — TLS 1.3 wire format for PQ key shares
// ─────────────────────────────────────────────────────────────────────────────

/// Named group identifier for a post-quantum KEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqGroup {
    /// ML-KEM-512 (FIPS 203, security category 1). IANA value: 0x0200.
    MlKem512 = 0x0200,
    /// ML-KEM-768 (FIPS 203, security category 3). IANA value: 0x0201.
    MlKem768 = 0x0201,
    /// ML-KEM-1024 (FIPS 203, security category 5). IANA value: 0x0202.
    MlKem1024 = 0x0202,
    /// X-Wing (ML-KEM-768 + X25519). Provisional IANA value: 0x11EB.
    XWing768X25519 = 0x11EB,
    /// Hybrid ML-KEM-1024 + ECDH P-384 (CNSA 2.0). Internal value: 0x0300.
    HybridMlKem1024P384 = 0x0300,
}

/// TLS 1.3 `key_share` wire encoding for post-quantum KEM public keys and
/// ciphertexts.
///
/// Wire format: `group_id(2) || payload_len(2) || payload`
pub struct PqKeyShare {
    /// The named group (KEM algorithm).
    pub group: PqGroup,
    /// The raw payload (encapsulation key or ciphertext bytes).
    pub payload: Vec<u8>,
}

impl PqKeyShare {
    /// Wrap an encapsulation key's raw bytes in a key share.
    pub fn encode_encap_key(group: PqGroup, key_bytes: &[u8]) -> Self {
        Self {
            group,
            payload: key_bytes.to_vec(),
        }
    }

    /// Wrap a ciphertext's raw bytes in a key share.
    pub fn encode_ciphertext(group: PqGroup, ct_bytes: &[u8]) -> Self {
        Self {
            group,
            payload: ct_bytes.to_vec(),
        }
    }

    /// Encode to wire format: `group_id(2) || length(2) || payload`.
    pub fn to_wire(&self) -> Vec<u8> {
        let len = self.payload.len();
        let mut out = Vec::with_capacity(4 + len);
        let gid = self.group as u16;
        out.extend_from_slice(&gid.to_be_bytes());
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from wire format.
    ///
    /// Returns [`CryptoError::Encoding`] if the bytes are too short,
    /// or [`CryptoError::UnsupportedAlgorithm`] for an unknown group id.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 4 {
            return Err(CryptoError::Encoding);
        }
        let group_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + payload_len {
            return Err(CryptoError::Encoding);
        }
        let group = match group_id {
            0x0200 => PqGroup::MlKem512,
            0x0201 => PqGroup::MlKem768,
            0x0202 => PqGroup::MlKem1024,
            0x11EB => PqGroup::XWing768X25519,
            0x0300 => PqGroup::HybridMlKem1024P384,
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        };
        Ok(Self {
            group,
            payload: bytes[4..4 + payload_len].to_vec(),
        })
    }

    /// Expected encapsulation key length (bytes) for each group.
    pub fn expected_encap_key_len(group: PqGroup) -> usize {
        match group {
            PqGroup::MlKem512 => 800,
            PqGroup::MlKem768 => 1184,
            PqGroup::MlKem1024 => 1568,
            PqGroup::XWing768X25519 => 1184 + 32, // mlkem_ek + x25519_pk
            PqGroup::HybridMlKem1024P384 => 1568 + 49, // mlkem_ek + p384_pk
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use oxicrypto_core::Kem;

    // ── X-Wing label sanity ───────────────────────────────────────────────────

    #[test]
    fn xwing_label_is_6_bytes() {
        // draft-connolly-cfrg-xwing-kem-04 §4 specifies a 6-byte label.
        assert_eq!(XWING_LABEL.len(), 6, "XWING_LABEL must be 6 bytes");
        // Verify exact bytes: \. // ^\ = 0x5c 0x2e 0x2f 0x2f 0x5e 0x5c
        assert_eq!(
            XWING_LABEL,
            &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
            "XWING_LABEL bytes must match draft §4 specification"
        );
    }

    // ── X-Wing round-trip ─────────────────────────────────────────────────────

    #[test]
    fn xwing768_round_trip() {
        let (dk, ek) = XWing768::kem_generate().expect("xwing generate");
        let (ct, ss_enc) = XWing768::kem_encapsulate(&ek).expect("xwing encapsulate");
        let ss_dec = XWing768::kem_decapsulate(&dk, &ct).expect("xwing decapsulate");
        assert_eq!(
            ss_enc.as_slice(),
            ss_dec.as_slice(),
            "X-Wing encap/decap shared secrets must match"
        );
    }

    #[test]
    fn xwing768_tamper_mlkem_ct() {
        let (dk, ek) = XWing768::kem_generate().expect("generate");
        let (mut ct, ss_enc) = XWing768::kem_encapsulate(&ek).expect("encapsulate");

        // Flip bits in the ML-KEM-768 ciphertext.
        let mut ct_bytes = ct.mlkem_ct.to_bytes();
        ct_bytes[0] ^= 0xff;
        ct.mlkem_ct =
            crate::mlkem::Ciphertext768::from_bytes(&ct_bytes).expect("from_bytes after flip");

        let ss_dec = XWing768::kem_decapsulate(&dk, &ct).expect("decapsulate tampered");
        // ML-KEM uses implicit rejection: decapsulate still succeeds but returns different SS.
        assert_ne!(
            ss_enc.as_slice(),
            ss_dec.as_slice(),
            "Tampered ML-KEM CT must produce different shared secret"
        );
    }

    #[test]
    fn xwing768_tamper_x25519_ct() {
        let (dk, ek) = XWing768::kem_generate().expect("generate");
        let (mut ct, ss_enc) = XWing768::kem_encapsulate(&ek).expect("encapsulate");

        // Flip bits in the X25519 ciphertext (ephemeral public key).
        ct.x25519_ct[0] ^= 0xff;

        // The X25519 DH with a tampered pk may produce an error (low-order) or
        // a different ss_x — either way the final SS must differ from ss_enc.
        let result = XWing768::kem_decapsulate(&dk, &ct);
        match result {
            Ok(ss_dec) => assert_ne!(
                ss_enc.as_slice(),
                ss_dec.as_slice(),
                "Tampered X25519 CT must produce different SS"
            ),
            Err(_) => {
                // Expected: some tampered keys hit low-order rejection.
            }
        }
    }

    // ── Hybrid ML-KEM-1024 + P-384 round-trip ────────────────────────────────

    #[test]
    fn hybrid_p384_round_trip() {
        let (dk, ek) = HybridKem1024P384::kem_generate().expect("hybrid generate");
        let (ct, ss_enc) = HybridKem1024P384::kem_encapsulate(&ek).expect("hybrid encapsulate");
        let ss_dec = HybridKem1024P384::kem_decapsulate(&dk, &ct).expect("hybrid decapsulate");
        assert_eq!(
            ss_enc.as_slice(),
            ss_dec.as_slice(),
            "Hybrid P-384 encap/decap shared secrets must match"
        );
    }

    #[test]
    fn hybrid_p384_tamper_mlkem_ct() {
        let (dk, ek) = HybridKem1024P384::kem_generate().expect("generate");
        let (mut ct, ss_enc) = HybridKem1024P384::kem_encapsulate(&ek).expect("encapsulate");

        // Flip bits in the ML-KEM-1024 ciphertext.
        let mut ct_bytes = ct.mlkem_ct.to_bytes();
        ct_bytes[0] ^= 0xff;
        ct.mlkem_ct = crate::mlkem::Ciphertext1024::from_bytes(&ct_bytes).expect("from_bytes");

        let ss_dec = HybridKem1024P384::kem_decapsulate(&dk, &ct).expect("decapsulate");
        // Combiner includes ct_m so even implicit-rejection-equal ss_m still changes SS.
        assert_ne!(
            ss_enc.as_slice(),
            ss_dec.as_slice(),
            "Tampered ML-KEM-1024 CT must produce different shared secret"
        );
    }

    // ── PqKeyShare encode / decode ────────────────────────────────────────────

    #[test]
    fn pq_key_share_encode_decode_roundtrip() {
        let payload = vec![0xABu8; 1184]; // ML-KEM-768 ek size
        let ks = PqKeyShare::encode_encap_key(PqGroup::MlKem768, &payload);
        let wire = ks.to_wire();
        assert_eq!(wire.len(), 4 + 1184);

        let decoded = PqKeyShare::from_wire(&wire).expect("from_wire");
        assert_eq!(decoded.group, PqGroup::MlKem768);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn pq_key_share_all_groups_roundtrip() {
        let groups = [
            (PqGroup::MlKem512, 800usize),
            (PqGroup::MlKem768, 1184),
            (PqGroup::MlKem1024, 1568),
            (PqGroup::XWing768X25519, 1216),
            (PqGroup::HybridMlKem1024P384, 1617),
        ];
        for (group, sz) in groups {
            let payload = vec![0x5Au8; sz];
            let wire = PqKeyShare::encode_encap_key(group, &payload).to_wire();
            let decoded = PqKeyShare::from_wire(&wire).expect("from_wire");
            assert_eq!(decoded.group, group, "group mismatch for {:?}", group);
            assert_eq!(decoded.payload.len(), sz, "len mismatch for {:?}", group);
        }
    }

    #[test]
    fn pq_key_share_short_bytes_error() {
        // 3 bytes — too short for the 4-byte header.
        let result = PqKeyShare::from_wire(&[0x02, 0x01, 0x00]);
        assert!(result.is_err(), "short bytes must return Err");
    }

    #[test]
    fn pq_key_share_truncated_payload_error() {
        // Header says payload is 100 bytes, but only 2 bytes follow.
        let mut wire = vec![0x02u8, 0x01, 0x00, 0x64]; // group=MlKem768, len=100
        wire.extend_from_slice(&[0xFFu8; 2]); // only 2 bytes, not 100
        let result = PqKeyShare::from_wire(&wire);
        assert!(result.is_err(), "truncated payload must return Err");
    }

    #[test]
    fn pq_key_share_unknown_group_error() {
        // group_id = 0xFFFF (unknown)
        let wire = [0xFFu8, 0xFF, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        let result = PqKeyShare::from_wire(&wire);
        assert!(
            result.is_err(),
            "unknown group must return UnsupportedAlgorithm"
        );
    }

    // ── expected_encap_key_len sanity check ───────────────────────────────────

    #[test]
    fn expected_encap_key_len_values() {
        assert_eq!(PqKeyShare::expected_encap_key_len(PqGroup::MlKem512), 800);
        assert_eq!(PqKeyShare::expected_encap_key_len(PqGroup::MlKem768), 1184);
        assert_eq!(PqKeyShare::expected_encap_key_len(PqGroup::MlKem1024), 1568);
        assert_eq!(
            PqKeyShare::expected_encap_key_len(PqGroup::XWing768X25519),
            1216
        );
        assert_eq!(
            PqKeyShare::expected_encap_key_len(PqGroup::HybridMlKem1024P384),
            1617
        );
    }

    // ── X-Wing KAT (draft-connolly-cfrg-xwing-kem-04 Appendix C, vector #1) ──
    //
    // This test verifies that our combiner produces the exact shared secret
    // from the published test vector, confirming byte-level interoperability
    // with the draft specification.
    //
    // Seed:    7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
    // ESeed:   3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2
    //          35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2
    // Expected SS: 555a071a8b7520ae95f8e635de8a5f87dbddcbef900576aad29ecdda5459c15a
    #[test]
    fn xwing768_kat_vector_1() {
        use crate::mlkem::MlKem768;
        use sha3::{Digest, Sha3_256};
        use shake::{ExtendableOutput, Shake128, Update as ShakeUpdate};
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

        // ── 1. Expand 32-byte seed via SHAKE128 → 96 bytes ──────────────────
        let seed =
            hex_to_bytes_32("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let mut shake = Shake128::default();
        ShakeUpdate::update(&mut shake, &seed);
        let mut expanded = [0u8; 96];
        {
            use shake::XofReader;
            let mut reader = shake.finalize_xof();
            reader.read(&mut expanded);
        }

        // First 64 bytes → ML-KEM-768 seed (d||z).
        let mlkem_seed: [u8; 64] = expanded[..64]
            .try_into()
            .expect("first 64 bytes of expansion");
        // Last 32 bytes → X25519 static secret key.
        let sk_x: [u8; 32] = expanded[64..96]
            .try_into()
            .expect("last 32 bytes of expansion");

        // ── 2. Derive keys ──────────────────────────────────────────────────
        let (_, mlkem_ek) = MlKem768::generate_deterministic(&mlkem_seed);
        let pk_x: [u8; 32] = *X25519PublicKey::from(&StaticSecret::from(sk_x)).as_bytes();

        // ── 3. Encapsulation seed ────────────────────────────────────────────
        let eseed = hex_to_bytes_64(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
             35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        );
        let m: [u8; 32] = eseed[..32].try_into().expect("m from eseed");
        let ek_x: [u8; 32] = eseed[32..64].try_into().expect("ek_x from eseed");

        // ── 4. ML-KEM-768 deterministic encapsulate ─────────────────────────
        let (mlkem_ct, ss_m) = mlkem_ek
            .encapsulate_deterministic(&m)
            .expect("mlkem deterministic encapsulate");

        // ── 5. X25519 ephemeral pk (ct_X) and shared secret (ss_X) ──────────
        let ct_x: [u8; 32] = *X25519PublicKey::from(&StaticSecret::from(ek_x)).as_bytes();
        let ss_x: [u8; 32] = StaticSecret::from(ek_x)
            .diffie_hellman(&X25519PublicKey::from(pk_x))
            .to_bytes();

        // ── 6. Convert ss_M to [u8; 32] ─────────────────────────────────────
        let ss_m_arr: [u8; 32] = ss_m.as_slice().try_into().expect("ss_m must be 32 bytes");

        // ── 7. Combiner: SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X) ─
        let mut h = Sha3_256::new();
        Digest::update(&mut h, XWING_LABEL);
        Digest::update(&mut h, ss_m_arr);
        Digest::update(&mut h, ss_x);
        Digest::update(&mut h, ct_x);
        Digest::update(&mut h, pk_x);
        let ss: [u8; 32] = h.finalize().into();

        // Verify ciphertext bytes match
        let ct_m_bytes = mlkem_ct.to_bytes();
        // The full X-Wing ciphertext is ct_M (1088 B) || ct_X (32 B) = 1120 B.
        // We skip full ciphertext comparison here since the draft ciphertext
        // is too large to embed verbatim; the shared secret comparison is the
        // authoritative check.
        assert_eq!(
            ct_m_bytes.len(),
            1088,
            "ML-KEM-768 ciphertext must be 1088 bytes"
        );

        // ── 8. Compare against expected shared secret ────────────────────────
        let expected_ss =
            hex_to_bytes_32("555a071a8b7520ae95f8e635de8a5f87dbddcbef900576aad29ecdda5459c15a");
        assert_eq!(
            ss, expected_ss,
            "X-Wing KAT vector #1: shared secret mismatch"
        );
    }

    // Hex decode helpers used only in KAT tests.

    fn hex_to_bytes_32(s: &str) -> [u8; 32] {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(s.len(), 64, "expected 64 hex chars for 32 bytes");
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex_pair = core::str::from_utf8(chunk).expect("utf8");
            out[i] = u8::from_str_radix(hex_pair, 16).expect("valid hex");
        }
        out
    }

    fn hex_to_bytes_64(s: &str) -> [u8; 64] {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(s.len(), 128, "expected 128 hex chars for 64 bytes");
        let mut out = [0u8; 64];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex_pair = core::str::from_utf8(chunk).expect("utf8");
            out[i] = u8::from_str_radix(hex_pair, 16).expect("valid hex");
        }
        out
    }
}
