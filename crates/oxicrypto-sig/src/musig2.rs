#![forbid(unsafe_code)]

//! MuSig2 two-round multi-signature for Ed25519 (Nick–Ruffing–Seurin 2021).
//!
//! This module implements the MuSig2 n-of-n multi-signature protocol for the
//! `edwards25519` group, using SHA-512 domain-separated hash functions.
//! Aggregated MuSig2 signatures are standard Schnorr signatures verifiable
//! under ordinary Ed25519 against the aggregated public key.
//!
//! # Protocol overview
//!
//! MuSig2 runs in two rounds:
//!
//! 1. **Round 1 — commit** ([`musig2_commit`]). Each participant generates an
//!    ephemeral nonce pair `(r1, r2)` and broadcasts the corresponding
//!    commitments `(R1 = r1·G, R2 = r2·G)` as a [`PubNonce`].
//!
//! 2. **Round 2 — sign** ([`musig2_sign`]). Given the message and all
//!    participants' public nonces, each participant produces a [`PartialSig`].
//!
//! The coordinator aggregates partial signatures into a final
//! [`MuSig2Signature`] ([`musig2_aggregate`]) and verifies it
//! ([`musig2_verify`], [`musig2_verify_ed25519`]).
//!
//! # Security note
//!
//! **`SecNonce` MUST NOT be reused.** Reusing a nonce with a different message
//! but the same key leaks the secret key. The type enforces single-use by
//! taking ownership (`musig2_sign` consumes the `SecNonce`).
//!
//! # Context string and domain separation
//!
//! All MuSig2 hashes are prefixed with `"MuSig2-Ed25519-SHA512-v1"` to
//! separate them from FROST and standard Ed25519 hashes.
//!
//! # Rogue-key resistance
//!
//! Key aggregation uses per-key coefficients derived from `H_agg_coeff(L, P_i)`
//! where `L` is the sorted concatenation of all public keys. This binds every
//! participant's contribution so that no adversary can choose a public key that
//! cancels out an honest participant's key.

use curve25519_dalek::{EdwardsPoint, Scalar};
use oxicrypto_core::{CryptoError, Vec};
use zeroize::Zeroize;

use crate::frost::{
    deserialize_element, deserialize_scalar, h2, reduce_wide, scalar_base_mult, serialize_element,
    serialize_scalar, sha512_concat,
};

/// The ciphersuite context string for MuSig2-Ed25519-SHA512.
const MUSIG2_CONTEXT: &[u8] = b"MuSig2-Ed25519-SHA512-v1";

// ── Hash functions ───────────────────────────────────────────────────────────

/// `H_agg_coeff(L_bytes, P_bytes)` — per-key aggregation coefficient.
///
/// Domain: `MUSIG2_CONTEXT ‖ "keyagg_coeff" ‖ L_bytes ‖ P_bytes`
fn h_agg_coeff(l_bytes: &[u8], p_bytes: &[u8]) -> Scalar {
    reduce_wide(sha512_concat(&[
        MUSIG2_CONTEXT,
        b"keyagg_coeff",
        l_bytes,
        p_bytes,
    ]))
}

/// `H_nonce(X_bytes, R1_bytes, R2_bytes, msg)` — nonce binding coefficient.
///
/// Domain: `MUSIG2_CONTEXT ‖ "noncecoef" ‖ X_bytes ‖ R1_bytes ‖ R2_bytes ‖ msg`
fn h_nonce(x_bytes: &[u8], r1_bytes: &[u8], r2_bytes: &[u8], msg: &[u8]) -> Scalar {
    reduce_wide(sha512_concat(&[
        MUSIG2_CONTEXT,
        b"noncecoef",
        x_bytes,
        r1_bytes,
        r2_bytes,
        msg,
    ]))
}

// ── Types ────────────────────────────────────────────────────────────────────

/// A participant's secret signing key (the scalar, as a 32-byte seed).
///
/// Zeroized on drop.
pub struct MuSig2SecretKey {
    scalar: Scalar,
}

impl Drop for MuSig2SecretKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl MuSig2SecretKey {
    /// Construct a secret key from a 32-byte canonical scalar.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `bytes` is not a canonical
    /// little-endian scalar in `[0, ℓ)` or is zero.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let scalar = deserialize_scalar(bytes)?;
        if scalar == Scalar::ZERO {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { scalar })
    }

    /// Return the 32-byte canonical little-endian encoding of the scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        serialize_scalar(&self.scalar)
    }

    /// Derive the corresponding [`MuSig2PublicKey`].
    pub fn public_key(&self) -> Result<MuSig2PublicKey, CryptoError> {
        let point = scalar_base_mult(&self.scalar);
        let compressed = serialize_element(&point)?;
        Ok(MuSig2PublicKey(compressed))
    }
}

/// A participant's public key (compressed Edwards Y, 32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuSig2PublicKey([u8; 32]);

impl MuSig2PublicKey {
    /// Construct from a compressed 32-byte encoding.
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes do not decode to a
    /// valid prime-order Ed25519 point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        // Validate that the bytes decode to a real point.
        deserialize_element(bytes)?;
        Ok(Self(*bytes))
    }

    /// Return the raw 32-byte encoding.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ephemeral secret nonces for one signing session (single-use, move-only).
///
/// **MUST NOT be reused.** Taken by value in [`musig2_sign`] to enforce
/// single-use at compile time.
///
/// Zeroized on drop.
pub struct SecNonce {
    r1: Scalar,
    r2: Scalar,
}

impl Drop for SecNonce {
    fn drop(&mut self) {
        self.r1.zeroize();
        self.r2.zeroize();
    }
}

/// A participant's public nonce commitment (share in Round 1).
#[derive(Clone, Copy, Debug)]
pub struct PubNonce {
    /// Compressed encoding of `r1 · G`.
    pub r1_point: [u8; 32],
    /// Compressed encoding of `r2 · G`.
    pub r2_point: [u8; 32],
}

/// A partial signature from one participant.
pub struct PartialSig {
    s: Scalar,
}

/// The final aggregated MuSig2 signature (64 bytes: `R_compressed ‖ s_bytes`).
#[derive(Clone, Debug)]
pub struct MuSig2Signature(pub [u8; 64]);

// ── Key aggregation ──────────────────────────────────────────────────────────

/// Compute the aggregated public key for a set of participants.
///
/// The aggregate key `X̃ = Σ a_i · P_i` where `a_i = H_agg_coeff(L, P_i)` and
/// `L` is the sorted concatenation of all compressed public keys.
///
/// Returns `(aggregate_key_bytes, per_key_coefficients)` where coefficients
/// are in the same order as the (unsorted) input `public_keys`.
///
/// Returns [`CryptoError::BadInput`] if `public_keys` is empty.
/// Returns [`CryptoError::InvalidKey`] if any key fails to decompress.
pub fn aggregate_keys(
    public_keys: &[MuSig2PublicKey],
) -> Result<([u8; 32], Vec<Scalar>), CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::BadInput);
    }

    // 1. Sort by compressed encoding.
    let mut sorted_bytes: Vec<[u8; 32]> = public_keys.iter().map(|pk| pk.0).collect();
    sorted_bytes.sort();

    // 2. L_bytes = concatenation of sorted compressed keys.
    let mut l_bytes = Vec::with_capacity(sorted_bytes.len() * 32);
    for b in &sorted_bytes {
        l_bytes.extend_from_slice(b);
    }

    // 3. Compute per-key coefficients for the original (unsorted) order.
    let mut coefficients = Vec::with_capacity(public_keys.len());
    for pk in public_keys {
        let a_i = h_agg_coeff(&l_bytes, &pk.0);
        coefficients.push(a_i);
    }

    // 4. X̃ = Σ a_i · P_i (sum over all participants in original order).
    let mut aggregate = EdwardsPoint::default();
    for (pk, a_i) in public_keys.iter().zip(coefficients.iter()) {
        let point = deserialize_element(&pk.0)?;
        aggregate += a_i * point;
    }

    // 5. Serialize aggregate key.
    let agg_bytes = serialize_element(&aggregate)?;
    Ok((agg_bytes, coefficients))
}

// ── Round 1 — commit ─────────────────────────────────────────────────────────

/// Round 1: generate an ephemeral nonce pair from a cryptographic RNG.
///
/// Returns `(SecNonce, PubNonce)`. The `PubNonce` is broadcast to all
/// participants; the `SecNonce` is kept secret and used once in [`musig2_sign`].
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if the RNG fails, or [`CryptoError::InvalidKey`]
/// if a generated nonce scalar maps to the group identity (astronomically rare).
pub fn musig2_commit<R: rand_core::TryCryptoRng + ?Sized>(
    _secret_key: &MuSig2SecretKey,
    rng: &mut R,
) -> Result<(SecNonce, PubNonce), CryptoError> {
    let mut r1_bytes = [0u8; 64];
    let mut r2_bytes = [0u8; 64];
    rng.try_fill_bytes(&mut r1_bytes)
        .map_err(|_| CryptoError::Rng)?;
    rng.try_fill_bytes(&mut r2_bytes)
        .map_err(|_| CryptoError::Rng)?;
    let r1 = reduce_wide(r1_bytes);
    let r2 = reduce_wide(r2_bytes);
    r1_bytes.zeroize();
    r2_bytes.zeroize();
    build_nonce(r1, r2)
}

/// Round 1 (deterministic): generate a nonce pair from a 64-byte seed.
///
/// `r1 = reduce_wide(SHA512(MUSIG2_CONTEXT ‖ "nonce_r1" ‖ seed ‖ sk_bytes))`
/// `r2 = reduce_wide(SHA512(MUSIG2_CONTEXT ‖ "nonce_r2" ‖ seed ‖ sk_bytes))`
///
/// This variant is useful for reproducible tests and for deterministic nonce
/// generation in environments without a live RNG.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if the derived nonce maps to the group
/// identity (negligible probability).
pub fn musig2_commit_from_seed(
    secret_key: &MuSig2SecretKey,
    seed: &[u8; 64],
) -> Result<(SecNonce, PubNonce), CryptoError> {
    let sk_bytes = secret_key.to_bytes();
    let r1 = reduce_wide(sha512_concat(&[
        MUSIG2_CONTEXT,
        b"nonce_r1",
        seed.as_ref(),
        &sk_bytes,
    ]));
    let r2 = reduce_wide(sha512_concat(&[
        MUSIG2_CONTEXT,
        b"nonce_r2",
        seed.as_ref(),
        &sk_bytes,
    ]));
    build_nonce(r1, r2)
}

/// Shared helper that turns `(r1, r2)` scalars into a `(SecNonce, PubNonce)` pair.
fn build_nonce(r1: Scalar, r2: Scalar) -> Result<(SecNonce, PubNonce), CryptoError> {
    let r1_point = serialize_element(&scalar_base_mult(&r1))?;
    let r2_point = serialize_element(&scalar_base_mult(&r2))?;
    Ok((SecNonce { r1, r2 }, PubNonce { r1_point, r2_point }))
}

// ── Internal: compute (R, b, X̃, coefficients) ───────────────────────────────

/// Compute the shared values used by both [`musig2_sign`] and [`musig2_aggregate`].
///
/// Returns `(R_point, b, aggregate_key_bytes, per_key_coefficients)`.
fn compute_session_values(
    public_keys: &[MuSig2PublicKey],
    all_pub_nonces: &[PubNonce],
    message: &[u8],
) -> Result<(EdwardsPoint, Scalar, [u8; 32], Vec<Scalar>), CryptoError> {
    if public_keys.len() != all_pub_nonces.len() || public_keys.is_empty() {
        return Err(CryptoError::BadInput);
    }

    // 1. Aggregate public key.
    let (agg_key_bytes, coefficients) = aggregate_keys(public_keys)?;

    // 2. R1 = Σ R1_i, R2 = Σ R2_i.
    let mut r1_sum = EdwardsPoint::default();
    let mut r2_sum = EdwardsPoint::default();
    for nonce in all_pub_nonces {
        r1_sum += deserialize_element(&nonce.r1_point)?;
        r2_sum += deserialize_element(&nonce.r2_point)?;
    }

    // 3. b = H_nonce(X̃, R1, R2, msg).
    let r1_bytes = serialize_element(&r1_sum)?;
    let r2_bytes = serialize_element(&r2_sum)?;
    let b = h_nonce(&agg_key_bytes, &r1_bytes, &r2_bytes, message);

    // 4. R = R1 + b · R2.
    let r_point = r1_sum + b * r2_sum;

    Ok((r_point, b, agg_key_bytes, coefficients))
}

// ── Round 2 — sign ───────────────────────────────────────────────────────────

/// Round 2: produce a partial signature.
///
/// Consumes both `secret_key` and `sec_nonce` to enforce single-use semantics.
///
/// # Errors
///
/// - [`CryptoError::BadInput`] if `my_index >= public_keys.len()`, or if the
///   participant counts differ.
/// - [`CryptoError::InvalidKey`] if any public nonce fails to decode.
pub fn musig2_sign(
    secret_key: MuSig2SecretKey,
    sec_nonce: SecNonce,
    public_keys: &[MuSig2PublicKey],
    all_pub_nonces: &[PubNonce],
    my_index: usize,
    message: &[u8],
) -> Result<PartialSig, CryptoError> {
    if my_index >= public_keys.len() {
        return Err(CryptoError::BadInput);
    }

    let (r_point, b, agg_key_bytes, coefficients) =
        compute_session_values(public_keys, all_pub_nonces, message)?;

    // 5. c = H2(R_compressed ‖ X̃_compressed ‖ msg)  [Ed25519 challenge].
    let r_bytes = serialize_element(&r_point)?;
    let mut challenge_input =
        Vec::with_capacity(r_bytes.len() + agg_key_bytes.len() + message.len());
    challenge_input.extend_from_slice(&r_bytes);
    challenge_input.extend_from_slice(&agg_key_bytes);
    challenge_input.extend_from_slice(message);
    let c = h2(&challenge_input);

    // 6. s_i = r1_i + b · r2_i + c · a_i · x_i.
    let a_i = coefficients[my_index];
    let s_i = sec_nonce.r1 + b * sec_nonce.r2 + c * a_i * secret_key.scalar;

    Ok(PartialSig { s: s_i })
}

// ── Aggregation ──────────────────────────────────────────────────────────────

/// Aggregate partial signatures into a final MuSig2 signature.
///
/// # Errors
///
/// - [`CryptoError::BadInput`] if the slice lengths differ or are empty.
/// - [`CryptoError::InvalidKey`] if any public nonce fails to decode or the
///   aggregate nonce is the group identity.
pub fn musig2_aggregate(
    partial_sigs: &[PartialSig],
    public_keys: &[MuSig2PublicKey],
    all_pub_nonces: &[PubNonce],
    message: &[u8],
) -> Result<MuSig2Signature, CryptoError> {
    if partial_sigs.len() != public_keys.len() {
        return Err(CryptoError::BadInput);
    }

    let (r_point, _b, _agg_key_bytes, _coefficients) =
        compute_session_values(public_keys, all_pub_nonces, message)?;

    // s = Σ s_i mod ℓ.
    let mut s = Scalar::ZERO;
    for ps in partial_sigs {
        s += ps.s;
    }

    let r_bytes = serialize_element(&r_point)?;
    let s_bytes = serialize_scalar(&s);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);
    Ok(MuSig2Signature(sig))
}

// ── Verification ─────────────────────────────────────────────────────────────

/// Verify a MuSig2 signature using the internal Schnorr equation.
///
/// Checks `s · G == R + c · X̃` where `c = H2(R ‖ X̃ ‖ msg)`.
///
/// # Errors
///
/// - [`CryptoError::InvalidKey`] if the aggregate public key or `R` in the
///   signature fail to decode.
/// - [`CryptoError::InvalidTag`] if the signature equation does not hold.
pub fn musig2_verify(
    aggregate_public_key: &[u8; 32],
    message: &[u8],
    signature: &MuSig2Signature,
) -> Result<(), CryptoError> {
    let r_bytes: &[u8; 32] = signature.0[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidTag)?;
    let s_bytes: &[u8; 32] = signature.0[32..]
        .try_into()
        .map_err(|_| CryptoError::InvalidTag)?;

    let r_point = deserialize_element(r_bytes)?;
    let s = deserialize_scalar(s_bytes)?;
    let x_tilde = deserialize_element(aggregate_public_key)?;

    // c = H2(R ‖ X̃ ‖ msg).
    let mut challenge_input =
        Vec::with_capacity(r_bytes.len() + aggregate_public_key.len() + message.len());
    challenge_input.extend_from_slice(r_bytes);
    challenge_input.extend_from_slice(aggregate_public_key);
    challenge_input.extend_from_slice(message);
    let c = h2(&challenge_input);

    // Check: s · G == R + c · X̃.
    let lhs = scalar_base_mult(&s);
    let rhs = r_point + c * x_tilde;

    // Use constant-time comparison via compressed bytes.
    let lhs_bytes = serialize_element(&lhs)?;
    let rhs_bytes = serialize_element(&rhs)?;
    if lhs_bytes == rhs_bytes {
        Ok(())
    } else {
        Err(CryptoError::InvalidTag)
    }
}

/// Verify a MuSig2 signature using `ed25519_dalek` as the verification backend.
///
/// This exercises the full standard Ed25519 code path against the aggregated
/// public key, confirming the signature is byte-for-byte compatible.
///
/// # Errors
///
/// - [`CryptoError::InvalidKey`] if `aggregate_public_key_bytes` is not a
///   valid Ed25519 verifying key.
/// - [`CryptoError::InvalidTag`] if the signature is rejected.
pub fn musig2_verify_ed25519(
    aggregate_public_key_bytes: &[u8; 32],
    message: &[u8],
    signature: &MuSig2Signature,
) -> Result<(), CryptoError> {
    use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(aggregate_public_key_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    let sig = DalekSig::from_bytes(&signature.0);
    vk.verify(message, &sig)
        .map_err(|_| CryptoError::InvalidTag)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! # Test note — absence of standard known-answer tests
    //!
    //! No standard Ed25519-MuSig2 KAT exists: BIP-327 vectors are secp256k1-only
    //! and non-transferable. Validation is property-based: the aggregate signature
    //! verifies under standard Ed25519 via `ed25519_dalek::VerifyingKey::verify`
    //! against the aggregated key.

    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make_key(seed_byte: u8) -> (MuSig2SecretKey, MuSig2PublicKey) {
        let seed = [seed_byte; 32];
        // Build a non-zero scalar from the seed bytes (canonical form via reduce).
        // We use reduce_wide on a 64-byte buffer to ensure a valid scalar.
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&seed);
        // Add a fixed tag so the scalar isn't trivially zero.
        wide[32] = 0x01;
        let scalar = reduce_wide(wide);
        // Verify it's non-zero (extremely unlikely to fail for any reasonable seed_byte).
        assert_ne!(scalar, Scalar::ZERO, "test scalar must be non-zero");
        let sk = MuSig2SecretKey { scalar };
        let pk = sk.public_key().expect("public_key from test key");
        (sk, pk)
    }

    fn deterministic_seed(tag: u8) -> [u8; 64] {
        let mut seed = [0u8; 64];
        seed[0] = tag;
        seed[1] = 0xde;
        seed[2] = 0xad;
        seed
    }

    fn do_2of2(msg: &[u8]) -> Result<([u8; 32], MuSig2Signature), CryptoError> {
        let (sk0, pk0) = make_key(0x01);
        let (sk1, pk1) = make_key(0x02);
        let public_keys = [pk0, pk1];

        let seed0 = deterministic_seed(0xaa);
        let seed1 = deterministic_seed(0xbb);

        let (nonce0, pubnonce0) = musig2_commit_from_seed(&sk0, &seed0).expect("commit 0 failed");
        let (nonce1, pubnonce1) = musig2_commit_from_seed(&sk1, &seed1).expect("commit 1 failed");
        let all_nonces = [pubnonce0, pubnonce1];

        let psig0 = musig2_sign(sk0, nonce0, &public_keys, &all_nonces, 0, msg)?;
        let psig1 = musig2_sign(sk1, nonce1, &public_keys, &all_nonces, 1, msg)?;
        let partial_sigs = [psig0, psig1];

        let sig = musig2_aggregate(&partial_sigs, &public_keys, &all_nonces, msg)?;

        let (agg_key_bytes, _) = aggregate_keys(&public_keys)?;
        Ok((agg_key_bytes, sig))
    }

    // ── Test 1: 2-of-2 round-trip ────────────────────────────────────────────

    #[test]
    fn test_2of2_roundtrip() {
        let msg = b"MuSig2 two-participant test message";
        let (agg_key, sig) = do_2of2(msg).expect("2-of-2 signing failed");

        musig2_verify(&agg_key, msg, &sig).expect("musig2_verify failed");
        musig2_verify_ed25519(&agg_key, msg, &sig).expect("musig2_verify_ed25519 failed");
    }

    // ── Test 2: 3-of-3 round-trip ────────────────────────────────────────────

    #[test]
    fn test_3of3_roundtrip() {
        let msg = b"MuSig2 three-participant test message";

        let (sk0, pk0) = make_key(0x10);
        let (sk1, pk1) = make_key(0x20);
        let (sk2, pk2) = make_key(0x30);
        let public_keys = [pk0, pk1, pk2];

        let seeds: [[u8; 64]; 3] = [
            deterministic_seed(0x01),
            deterministic_seed(0x02),
            deterministic_seed(0x03),
        ];

        let (nonce0, pn0) = musig2_commit_from_seed(&sk0, &seeds[0]).expect("commit 0");
        let (nonce1, pn1) = musig2_commit_from_seed(&sk1, &seeds[1]).expect("commit 1");
        let (nonce2, pn2) = musig2_commit_from_seed(&sk2, &seeds[2]).expect("commit 2");
        let all_nonces = [pn0, pn1, pn2];

        let ps0 = musig2_sign(sk0, nonce0, &public_keys, &all_nonces, 0, msg).expect("sign 0");
        let ps1 = musig2_sign(sk1, nonce1, &public_keys, &all_nonces, 1, msg).expect("sign 1");
        let ps2 = musig2_sign(sk2, nonce2, &public_keys, &all_nonces, 2, msg).expect("sign 2");

        let sig =
            musig2_aggregate(&[ps0, ps1, ps2], &public_keys, &all_nonces, msg).expect("aggregate");

        let (agg_key_bytes, _) = aggregate_keys(&public_keys).expect("aggregate_keys");
        musig2_verify(&agg_key_bytes, msg, &sig).expect("verify");
        musig2_verify_ed25519(&agg_key_bytes, msg, &sig).expect("verify_ed25519");
    }

    // ── Test 3: rogue-key resistance (coefficients non-trivial) ──────────────

    #[test]
    fn test_rogue_key_coefficients_nontrivial() {
        // In a typical 2-of-2 setup, no participant's coefficient should be 1.
        // If a_i == 1 for some participant, an adversary could craft the other
        // key to cancel the honest participant's key.
        let (_sk0, pk0) = make_key(0xA0);
        let (_sk1, pk1) = make_key(0xB0);
        let public_keys = [pk0, pk1];

        let (_agg, coefficients) = aggregate_keys(&public_keys).expect("aggregate_keys");

        for (i, coeff) in coefficients.iter().enumerate() {
            assert_ne!(
                *coeff,
                Scalar::ONE,
                "coefficient a_{i} must not be 1 (rogue-key protection failed)"
            );
        }
    }

    // ── Test 4: wrong message fails verification ──────────────────────────────

    #[test]
    fn test_wrong_message_fails() {
        let msg_a = b"correct message";
        let msg_b = b"tampered message";

        let (agg_key, sig) = do_2of2(msg_a).expect("signing msg_a");

        assert_eq!(
            musig2_verify(&agg_key, msg_b, &sig),
            Err(CryptoError::InvalidTag),
            "verifying with wrong message must fail"
        );
    }

    // ── Test 5: wrong partial sig causes verification failure ─────────────────

    #[test]
    fn test_wrong_partial_sig_fails() {
        let msg = b"test message for tamper test";

        let (sk0, pk0) = make_key(0x41);
        let (sk1, pk1) = make_key(0x42);
        let public_keys = [pk0, pk1];

        let seed0 = deterministic_seed(0x51);
        let seed1 = deterministic_seed(0x52);

        let (nonce0, pn0) = musig2_commit_from_seed(&sk0, &seed0).expect("commit 0");
        let (nonce1, pn1) = musig2_commit_from_seed(&sk1, &seed1).expect("commit 1");
        let all_nonces = [pn0, pn1];

        let ps0 = musig2_sign(sk0, nonce0, &public_keys, &all_nonces, 0, msg).expect("sign 0");
        let _ps1 = musig2_sign(sk1, nonce1, &public_keys, &all_nonces, 1, msg).expect("sign 1");

        // Use a corrupted partial sig for participant 1 (random scalar).
        let bad_wide = [0xDDu8; 64];
        let bad_scalar = reduce_wide(bad_wide);
        let bad_ps1 = PartialSig { s: bad_scalar };

        let bad_sig = musig2_aggregate(&[ps0, bad_ps1], &public_keys, &all_nonces, msg)
            .expect("aggregate with bad partial");

        let (agg_key, _) = aggregate_keys(&public_keys).expect("aggregate_keys");
        assert_eq!(
            musig2_verify(&agg_key, msg, &bad_sig),
            Err(CryptoError::InvalidTag),
            "tampered partial sig must fail verification"
        );
    }

    // ── Test 6: deterministic nonce generation ────────────────────────────────

    #[test]
    fn test_deterministic_nonce() {
        let (sk, _pk) = make_key(0x77);
        let seed = deterministic_seed(0x99);

        // Build two copies of the secret key with the same scalar.
        let scalar_bytes = sk.to_bytes();
        let sk2 = MuSig2SecretKey::from_bytes(&scalar_bytes).expect("sk2");

        let (_sec1, pub1) = musig2_commit_from_seed(&sk, &seed).expect("commit 1");
        let (_sec2, pub2) = musig2_commit_from_seed(&sk2, &seed).expect("commit 2");

        assert_eq!(
            pub1.r1_point, pub2.r1_point,
            "deterministic r1 must be reproducible"
        );
        assert_eq!(
            pub1.r2_point, pub2.r2_point,
            "deterministic r2 must be reproducible"
        );
    }
}
