#![forbid(unsafe_code)]

//! BIP-340 Schnorr signatures over secp256k1 (Bitcoin / Taproot / Lightning).
//!
//! This module wraps the pure-Rust [`k256`] `schnorr` implementation and exposes
//! it through the OxiCrypto [`Signer`] / [`Verifier`] trait surface, adding
//! x-only public-key handling, [`SecretKey`]/zeroize wrapping, BIP-340
//! auxiliary-randomness nonce support, and an optional SHA-256 pre-hash
//! convenience.
//!
//! # BIP-340 semantics
//!
//! * **Secret key** — 32 bytes (a secp256k1 scalar in `1..n`).
//! * **Public key** — 32-byte **x-only** encoding (`P_x`). The even-`Y`
//!   representative is implied; verification performs `lift_x` to recover the
//!   point with even `Y`.
//! * **Signature** — 64 bytes, `R_x ‖ s`.
//! * **Challenge** — `e = int(tagged_hash("BIP0340/challenge", R_x ‖ P_x ‖ m)) mod n`.
//! * **Nonce** — derived per BIP-340 from the secret key, public key, message,
//!   and 32 bytes of auxiliary randomness via `tagged_hash("BIP0340/aux", ...)`
//!   and `tagged_hash("BIP0340/nonce", ...)`. Even-`Y` normalization is applied
//!   to both `R` and the effective signing scalar.
//!
//! # Message handling
//!
//! BIP-340 signs the message bytes `m` **directly** (the message is absorbed
//! into the tagged hashes; it is *not* pre-hashed by the scheme). The raw
//! BIP-340 surface is therefore exposed by [`SchnorrBip340::sign_with_aux`],
//! the [`Signer::sign`] trait method, and [`SchnorrBip340::verify_message`] /
//! the [`Verifier::verify`] trait method — all of which operate on `m` as
//! given. Historically BIP-340 was specified for 32-byte messages; the 2022
//! revision generalized `m` to an arbitrary-length byte string, which is what
//! this module accepts.
//!
//! For callers who want to sign an *application* message of arbitrary length
//! with a fixed-size digest under explicit domain control, the inherent
//! [`SchnorrBip340::sign_sha256`] / [`SchnorrBip340::verify_sha256`] helpers
//! SHA-256-hash the input first and then run BIP-340 over the 32-byte digest.
//! This pre-hash convenience is **not** interchangeable with the raw trait
//! methods: a signature produced by `sign_sha256(msg)` verifies with
//! `verify_sha256(msg)` (equivalently `verify_message(sha256(msg))`), never
//! with `verify_message(msg)`.
//!
//! # Errors
//!
//! All failures map to [`CryptoError`]:
//! * [`CryptoError::InvalidKey`] — malformed secret key or x-only public key
//!   (wrong length, not a valid `lift_x` coordinate, exceeds the field size).
//! * [`CryptoError::InvalidTag`] — malformed (non-64-byte / non-canonical)
//!   signature encoding.
//! * [`CryptoError::Sign`] — signing failed, or a syntactically valid signature
//!   failed BIP-340 verification.
//! * [`CryptoError::BufferTooSmall`] — the [`Signer::sign`] output buffer is
//!   shorter than 64 bytes.

use oxicrypto_core::{CryptoError, SecretKey, Signer, Vec, Verifier};

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Length in bytes of a BIP-340 secret key (a secp256k1 scalar).
pub const SECRET_KEY_LEN: usize = 32;

/// Length in bytes of a BIP-340 x-only public key (`P_x`).
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length in bytes of a BIP-340 signature (`R_x ‖ s`).
pub const SIGNATURE_LEN: usize = 64;

/// All-zero auxiliary randomness — the deterministic BIP-340 nonce path.
///
/// Using all-zero `aux_rand` is explicitly permitted by BIP-340 ("the
/// resulting nonce ... is still secure") and yields a deterministic signature
/// for a given `(sk, m)` pair. This is the auxiliary value used by the
/// [`Signer::sign`] trait method.
const ZERO_AUX: [u8; 32] = [0u8; 32];

/// BIP-340 Schnorr signatures over secp256k1.
///
/// Zero-sized dispatcher implementing [`Signer`] and [`Verifier`]. Construct
/// with [`SchnorrBip340::default`] (or the `SchnorrBip340` literal) and call the
/// trait methods, or use the inherent helpers for x-only key derivation,
/// explicit auxiliary randomness, and the SHA-256 pre-hash convenience.
///
/// # Examples
///
/// ```
/// use oxicrypto_core::{Signer, Verifier};
/// use oxicrypto_sig::SchnorrBip340;
///
/// let scheme = SchnorrBip340;
/// // BIP-340 test-vector secret key #1.
/// let sk = [
///     0xB7, 0xE1, 0x51, 0x62, 0x8A, 0xED, 0x2A, 0x6A, 0xBF, 0x71, 0x58, 0x80,
///     0x9C, 0xF4, 0xF3, 0xC7, 0x62, 0xE7, 0x16, 0x0F, 0x38, 0xB4, 0xDA, 0x56,
///     0xA7, 0x84, 0xD9, 0x04, 0x51, 0x90, 0xCF, 0xEF,
/// ];
/// let pk = scheme.derive_public_key(&sk).expect("derive x-only key");
/// assert_eq!(pk.len(), 32);
///
/// let msg = b"hello bip-340";
/// let mut sig = [0u8; 64];
/// let n = Signer::sign(&scheme, &sk, msg, &mut sig).expect("sign");
/// assert_eq!(n, 64);
/// scheme.verify(&pk, msg, &sig).expect("verify");
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct SchnorrBip340;

impl SchnorrBip340 {
    /// Parse a 32-byte secret key into a zeroizing [`SecretKey`], validating it
    /// as a usable secp256k1 signing scalar.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `sk` is not exactly 32 bytes or is
    /// not a valid scalar in `1..n`.
    #[must_use = "result must be checked"]
    pub fn parse_secret_key(sk: &[u8]) -> Result<SecretKey<SECRET_KEY_LEN>, CryptoError> {
        // Validate by attempting to build the signing key, then return the
        // bytes wrapped in the zeroizing container.
        let secret = SecretKey::<SECRET_KEY_LEN>::from_slice(sk)?;
        let _ = signing_key_from_secret(&secret)?;
        Ok(secret)
    }

    /// Derive the 32-byte BIP-340 **x-only** public key (`P_x`) from a 32-byte
    /// secret key.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `sk` is not a valid secret key.
    #[must_use = "result must be checked"]
    pub fn derive_public_key(&self, sk: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
        let secret = SecretKey::<SECRET_KEY_LEN>::from_slice(sk)?;
        let signing_key = signing_key_from_secret(&secret)?;
        Ok(verifying_key_to_xonly(signing_key.verifying_key()))
    }

    /// Parse a 32-byte x-only public key, validating it as a curve point via
    /// BIP-340 `lift_x`, and return its canonical 32-byte encoding.
    ///
    /// Useful for key round-trip / validation. Returns
    /// [`CryptoError::InvalidKey`] if the bytes are not a valid x-only point
    /// (e.g. not on the curve, or `x >= p`).
    #[must_use = "result must be checked"]
    pub fn parse_public_key(pk: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
        let verifying_key = verifying_key_from_xonly(pk)?;
        Ok(verifying_key_to_xonly(&verifying_key))
    }

    /// Sign `msg` under BIP-340 with caller-supplied 32-byte auxiliary
    /// randomness, returning the 64-byte signature `R_x ‖ s`.
    ///
    /// `aux_rand` SHOULD be 32 fresh random bytes for side-channel hardening;
    /// passing all-zero bytes selects the deterministic nonce path (see
    /// [`SchnorrBip340::sign`]). The message `m` is signed directly per BIP-340
    /// (no pre-hashing).
    ///
    /// Returns [`CryptoError::InvalidKey`] for a bad secret key, or
    /// [`CryptoError::Sign`] if the underlying signing operation fails.
    #[must_use = "signature result must be checked"]
    pub fn sign_with_aux(
        &self,
        sk: &[u8],
        msg: &[u8],
        aux_rand: &[u8; 32],
    ) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        let secret = SecretKey::<SECRET_KEY_LEN>::from_slice(sk)?;
        let signing_key = signing_key_from_secret(&secret)?;
        let signature = signing_key
            .sign_raw(msg, aux_rand)
            .map_err(|_| CryptoError::Sign)?;
        Ok(signature.to_bytes())
    }

    /// Verify a 64-byte BIP-340 signature over `msg` against a 32-byte x-only
    /// public key. The message `m` is verified directly per BIP-340 (no
    /// pre-hashing).
    ///
    /// Returns `Ok(())` on success, [`CryptoError::InvalidKey`] for a bad
    /// public key, [`CryptoError::InvalidTag`] for a malformed signature
    /// encoding, or [`CryptoError::Sign`] if a well-formed signature fails to
    /// verify.
    #[must_use = "verification result must be checked"]
    pub fn verify_message(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = verifying_key_from_xonly(pk)?;
        let signature = parse_signature(sig)?;
        verifying_key
            .verify_raw(msg, &signature)
            .map_err(|_| CryptoError::Sign)
    }

    /// SHA-256 pre-hash convenience: hash an arbitrary-length application
    /// message with SHA-256 and BIP-340-sign the resulting 32-byte digest,
    /// using all-zero auxiliary randomness.
    ///
    /// The produced signature verifies with [`SchnorrBip340::verify_sha256`]
    /// (equivalently `verify_message(sha256(msg))`); it does **not** verify with
    /// [`SchnorrBip340::verify_message`] over the original `msg`.
    #[must_use = "signature result must be checked"]
    pub fn sign_sha256(&self, sk: &[u8], msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        let digest = sha256(msg);
        self.sign_with_aux(sk, &digest, &ZERO_AUX)
    }

    /// SHA-256 pre-hash convenience: verify a BIP-340 signature produced by
    /// [`SchnorrBip340::sign_sha256`] over `msg`.
    #[must_use = "verification result must be checked"]
    pub fn verify_sha256(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let digest = sha256(msg);
        self.verify_message(pk, &digest, sig)
    }
}

impl Signer for SchnorrBip340 {
    fn name(&self) -> &'static str {
        "Schnorr-BIP340"
    }

    fn signature_len(&self) -> usize {
        SIGNATURE_LEN
    }

    /// Sign `msg` under BIP-340 using the **deterministic** (all-zero
    /// auxiliary randomness) nonce path, writing the 64-byte signature into
    /// `sig_out`.
    ///
    /// `sk` must be the raw 32-byte secret key; `msg` is signed directly per
    /// BIP-340 (no pre-hashing — use [`SchnorrBip340::sign_sha256`] for the
    /// SHA-256 pre-hash convenience). For caller-supplied auxiliary randomness
    /// use [`SchnorrBip340::sign_with_aux`].
    ///
    /// Returns [`CryptoError::BufferTooSmall`] if `sig_out` is shorter than 64
    /// bytes.
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < SIGNATURE_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let signature = self.sign_with_aux(sk, msg, &ZERO_AUX)?;
        sig_out[..SIGNATURE_LEN].copy_from_slice(&signature);
        Ok(SIGNATURE_LEN)
    }
}

impl Verifier for SchnorrBip340 {
    fn name(&self) -> &'static str {
        "Schnorr-BIP340"
    }

    /// Verify a 64-byte BIP-340 signature over `msg` against the 32-byte x-only
    /// public key `pk`. Returns [`CryptoError::Sign`] on verification failure.
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        self.verify_message(pk, msg, sig)
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Build a [`SigningKey`] from a zeroizing 32-byte secret, mapping any error to
/// [`CryptoError::InvalidKey`].
fn signing_key_from_secret(secret: &SecretKey<SECRET_KEY_LEN>) -> Result<SigningKey, CryptoError> {
    // `SigningKey::from_bytes` takes `&FieldBytes` (a `hybrid_array::Array`),
    // which converts from a `&[u8; 32]` via `Into`.
    let field_bytes: &k256::FieldBytes = secret.as_bytes().into();
    SigningKey::from_bytes(field_bytes).map_err(|_| CryptoError::InvalidKey)
}

/// Parse a 32-byte x-only public key into a [`VerifyingKey`] (BIP-340
/// `lift_x`), mapping any error to [`CryptoError::InvalidKey`].
fn verifying_key_from_xonly(pk: &[u8]) -> Result<VerifyingKey, CryptoError> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    VerifyingKey::from_slice(pk).map_err(|_| CryptoError::InvalidKey)
}

/// Serialize a [`VerifyingKey`] to its canonical 32-byte x-only encoding.
fn verifying_key_to_xonly(vk: &VerifyingKey) -> [u8; PUBLIC_KEY_LEN] {
    let field_bytes = vk.to_bytes();
    let mut out = [0u8; PUBLIC_KEY_LEN];
    // `FieldBytes` is a 32-byte array view; copy element-wise via its slice.
    out.copy_from_slice(field_bytes.as_slice());
    out
}

/// Parse a 64-byte BIP-340 signature, mapping any error to
/// [`CryptoError::InvalidTag`].
fn parse_signature(sig: &[u8]) -> Result<Signature, CryptoError> {
    if sig.len() != SIGNATURE_LEN {
        return Err(CryptoError::InvalidTag);
    }
    Signature::try_from(sig).map_err(|_| CryptoError::InvalidTag)
}

/// Compute the SHA-256 digest of `msg` as a 32-byte array.
fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Convenience: produce a heap-allocated `Vec<u8>` signature with explicit
/// auxiliary randomness. Mirrors [`SchnorrBip340::sign_with_aux`] but returns a
/// `Vec` for callers that prefer an owned buffer over a fixed array.
#[must_use = "signature result must be checked"]
pub fn schnorr_bip340_sign_with_aux(
    sk: &[u8],
    msg: &[u8],
    aux_rand: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let scheme = SchnorrBip340;
    Ok(scheme.sign_with_aux(sk, msg, aux_rand)?.to_vec())
}
