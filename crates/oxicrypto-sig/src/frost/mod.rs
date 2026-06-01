#![forbid(unsafe_code)]

//! FROST(Ed25519, SHA-512) `t`-of-`n` threshold Schnorr signatures (RFC 9591).
//!
//! This module implements the Flexible Round-Optimized Schnorr Threshold
//! (FROST) signing protocol for the `FROST(Ed25519, SHA-512)` ciphersuite of
//! [RFC 9591], whose `contextString` is `"FROST-ED25519-SHA512-v1"`. Aggregated
//! FROST signatures are byte-for-byte ordinary Ed25519 signatures: they verify
//! under standard Ed25519 verification ([RFC 8032] §5.1.7) as well as under the
//! FROST group equation.
//!
//! # Protocol overview
//!
//! FROST splits an Ed25519 signing key `s` among `n` participants using Shamir
//! secret sharing such that any `t` of them can jointly produce a signature,
//! while fewer than `t` learn nothing. A *trusted dealer* performs key
//! generation ([`keygen`]); signing then proceeds in two rounds coordinated by
//! a Coordinator:
//!
//! 1. **Round one — commitment** ([`round1`]). Each participant generates a
//!    one-time `(hiding, binding)` nonce pair and publishes the corresponding
//!    pair of commitments.
//! 2. **Round two — signature share** ([`round2`]). Given the message and the
//!    list of all participants' commitments, each participant produces a
//!    signature share.
//!
//! The Coordinator then **aggregates** the shares into the final `(R, z)`
//! signature ([`aggregate()`]) and SHOULD verify it before publishing.
//!
//! # Group and hashes
//!
//! Group math is provided by [`curve25519_dalek`] over `edwards25519`: the
//! [`Scalar`] field is arithmetic mod the group order `ℓ = 2^252 +
//! 27742317777372353535851937790883648493`, and group elements are
//! [`EdwardsPoint`]s. Serialization follows RFC 9591 §6.1: scalars are 32-byte
//! little-endian, and elements are compressed Edwards `Y` coordinates.
//!
//! The five domain-separated hashes are built from SHA-512 (RFC 9591 §6.1):
//!
//! * `H1(m) = SHA512(contextString ‖ "rho"   ‖ m)` reduced mod `ℓ`
//! * `H2(m) = SHA512(m)` reduced mod `ℓ` — **plain SHA-512, no context string**,
//!   so the FROST challenge is identical to the standard Ed25519 challenge.
//! * `H3(m) = SHA512(contextString ‖ "nonce" ‖ m)` reduced mod `ℓ`
//! * `H4(m) = SHA512(contextString ‖ "msg"   ‖ m)`
//! * `H5(m) = SHA512(contextString ‖ "com"   ‖ m)`
//!
//! # Errors
//!
//! Fallible operations return [`CryptoError`]. Malformed scalars/points map to
//! [`CryptoError::InvalidKey`], malformed signatures/shares to
//! [`CryptoError::InvalidTag`], protocol misuse / bad parameters to
//! [`CryptoError::BadInput`], and signature/share verification failure to
//! [`CryptoError::Sign`].
//!
//! [RFC 9591]: https://www.rfc-editor.org/rfc/rfc9591.html
//! [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032.html

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, traits::IsIdentity,
    EdwardsPoint, Scalar,
};
use oxicrypto_core::{CryptoError, Vec};
use sha2::{Digest, Sha512};

pub mod aggregate;
pub mod keygen;
pub mod round1;
pub mod round2;

#[cfg(test)]
mod tests;

pub use aggregate::{aggregate, verify_signature, Signature};
pub use keygen::{
    trusted_dealer_keygen, trusted_dealer_keygen_with_coefficients, KeyPackage, PublicKeyPackage,
    SecretShare,
};
pub use round1::{commit, SigningCommitments, SigningNonces};
pub use round2::{sign, verify_signature_share, SignatureShare};

/// The ciphersuite context string for `FROST(Ed25519, SHA-512)` (RFC 9591 §6.1).
pub const CONTEXT_STRING: &[u8] = b"FROST-ED25519-SHA512-v1";

/// Serialized length of a [`Scalar`] (`Ns = 32`, RFC 9591 §6.1).
pub const SCALAR_LEN: usize = 32;

/// Serialized length of an [`EdwardsPoint`] (`Ne = 32`, RFC 9591 §6.1).
pub const ELEMENT_LEN: usize = 32;

/// Serialized length of a FROST signature `SerializeElement(R) ‖ SerializeScalar(z)`.
pub const SIGNATURE_LEN: usize = ELEMENT_LEN + SCALAR_LEN;

// ── Identifiers ─────────────────────────────────────────────────────────────

/// A participant identifier: a non-zero [`Scalar`] (RFC 9591 §5).
///
/// Identifiers are the x-coordinates of the Shamir secret-sharing polynomial
/// and MUST be distinct and non-zero. The trusted-dealer keygen in this crate
/// assigns identifiers `1, 2, …, n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identifier(Scalar);

impl Identifier {
    /// Construct an identifier from a `u16` index, which MUST be non-zero.
    ///
    /// Returns [`CryptoError::BadInput`] if `index == 0`.
    #[must_use = "result must be checked"]
    pub fn new(index: u16) -> Result<Self, CryptoError> {
        if index == 0 {
            return Err(CryptoError::BadInput);
        }
        Ok(Self(Scalar::from(u64::from(index))))
    }

    /// Construct an identifier from a raw [`Scalar`], which MUST be non-zero.
    ///
    /// Returns [`CryptoError::BadInput`] if `scalar` is zero.
    #[must_use = "result must be checked"]
    pub fn from_scalar(scalar: Scalar) -> Result<Self, CryptoError> {
        if scalar == Scalar::ZERO {
            return Err(CryptoError::BadInput);
        }
        Ok(Self(scalar))
    }

    /// Parse an identifier from its 32-byte little-endian canonical encoding.
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes are not a canonical
    /// scalar, or [`CryptoError::BadInput`] if the scalar is zero.
    #[must_use = "result must be checked"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let scalar = deserialize_scalar(bytes)?;
        Self::from_scalar(scalar)
    }

    /// The underlying [`Scalar`] value.
    #[must_use]
    pub fn as_scalar(&self) -> Scalar {
        self.0
    }

    /// The 32-byte little-endian canonical encoding of this identifier.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SCALAR_LEN] {
        self.0.to_bytes()
    }
}

// ── Group operations (RFC 9591 §3.1, §6.1) ──────────────────────────────────

/// `G.ScalarBaseMult(s)` — multiply the Ed25519 basepoint `B` by `s`.
#[must_use]
pub(crate) fn scalar_base_mult(s: &Scalar) -> EdwardsPoint {
    s * ED25519_BASEPOINT_POINT
}

/// `G.SerializeElement(A)` — the compressed Edwards encoding of `A`
/// (RFC 8032 §5.1.2). Per RFC 9591 §6.1 this additionally rejects the identity
/// element.
///
/// Returns [`CryptoError::InvalidKey`] if `point` is the group identity.
#[must_use = "result must be checked"]
pub(crate) fn serialize_element(point: &EdwardsPoint) -> Result<[u8; ELEMENT_LEN], CryptoError> {
    if point.is_identity() {
        return Err(CryptoError::InvalidKey);
    }
    Ok(point.compress().to_bytes())
}

/// `G.DeserializeElement(buf)` — decode a compressed Edwards point
/// (RFC 8032 §5.1.3). Per RFC 9591 §6.1 this additionally rejects the identity
/// element and any point outside the prime-order subgroup.
///
/// Returns [`CryptoError::InvalidKey`] on a wrong length, a non-canonical /
/// non-decodable encoding, the identity element, or a point with torsion.
#[must_use = "result must be checked"]
pub(crate) fn deserialize_element(buf: &[u8]) -> Result<EdwardsPoint, CryptoError> {
    if buf.len() != ELEMENT_LEN {
        return Err(CryptoError::InvalidKey);
    }
    let mut bytes = [0u8; ELEMENT_LEN];
    bytes.copy_from_slice(buf);
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or(CryptoError::InvalidKey)?;
    if point.is_identity() || !point.is_torsion_free() {
        return Err(CryptoError::InvalidKey);
    }
    Ok(point)
}

/// `G.SerializeScalar(s)` — 32-byte little-endian encoding (RFC 9591 §6.1).
#[must_use]
pub(crate) fn serialize_scalar(s: &Scalar) -> [u8; SCALAR_LEN] {
    s.to_bytes()
}

/// `G.DeserializeScalar(buf)` — decode a canonical 32-byte little-endian scalar
/// in `[0, ℓ)` (RFC 9591 §6.1). The top three bits MUST be zero.
///
/// Returns [`CryptoError::InvalidKey`] on a wrong length or a non-canonical
/// (out-of-range) encoding.
#[must_use = "result must be checked"]
pub(crate) fn deserialize_scalar(buf: &[u8]) -> Result<Scalar, CryptoError> {
    if buf.len() != SCALAR_LEN {
        return Err(CryptoError::InvalidKey);
    }
    let mut bytes = [0u8; SCALAR_LEN];
    bytes.copy_from_slice(buf);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or(CryptoError::InvalidKey)
}

// ── Hash functions (RFC 9591 §6.1) ──────────────────────────────────────────

/// Reduce a 64-byte SHA-512 digest to a [`Scalar`] mod `ℓ`, interpreting the
/// digest as a little-endian integer (`Scalar::from_bytes_mod_order_wide`).
#[must_use]
fn reduce_wide(digest: [u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&digest)
}

/// SHA-512 over the concatenation of `parts`, returning the 64-byte digest.
#[must_use]
fn sha512_concat(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// `H1(m) = SHA512(contextString ‖ "rho" ‖ m)` reduced mod `ℓ` (RFC 9591 §6.1).
/// Used to derive binding factors.
#[must_use]
pub(crate) fn h1(m: &[u8]) -> Scalar {
    reduce_wide(sha512_concat(&[CONTEXT_STRING, b"rho", m]))
}

/// `H2(m) = SHA512(m)` reduced mod `ℓ` (RFC 9591 §6.1).
///
/// **Plain SHA-512 with NO context string** — this is what makes the FROST
/// challenge identical to the standard Ed25519 challenge (RFC 8032 §5.1.6),
/// allowing aggregate signatures to verify under ordinary Ed25519.
#[must_use]
pub(crate) fn h2(m: &[u8]) -> Scalar {
    reduce_wide(sha512_concat(&[m]))
}

/// `H3(m) = SHA512(contextString ‖ "nonce" ‖ m)` reduced mod `ℓ`
/// (RFC 9591 §6.1). Used by `nonce_generate`.
#[must_use]
pub(crate) fn h3(m: &[u8]) -> Scalar {
    reduce_wide(sha512_concat(&[CONTEXT_STRING, b"nonce", m]))
}

/// `H4(m) = SHA512(contextString ‖ "msg" ‖ m)` (RFC 9591 §6.1). The full
/// 64-byte digest (the "message hash") used inside binding-factor computation.
#[must_use]
pub(crate) fn h4(m: &[u8]) -> [u8; 64] {
    sha512_concat(&[CONTEXT_STRING, b"msg", m])
}

/// `H5(m) = SHA512(contextString ‖ "com" ‖ m)` (RFC 9591 §6.1). The full
/// 64-byte digest of the encoded commitment list used inside binding-factor
/// computation.
#[must_use]
pub(crate) fn h5(m: &[u8]) -> [u8; 64] {
    sha512_concat(&[CONTEXT_STRING, b"com", m])
}

// ── Binding factors, group commitment, challenge (RFC 9591 §4.3–§4.6) ───────

/// `encode_group_commitment_list(commitment_list)` (RFC 9591 §4.3).
///
/// Encodes each `(identifier, hiding_commitment, binding_commitment)` triple as
/// `SerializeScalar(id) ‖ SerializeElement(D_i) ‖ SerializeElement(E_i)` and
/// concatenates them. `commitment_list` MUST be sorted ascending by identifier.
///
/// Returns [`CryptoError::InvalidKey`] if any commitment is the identity
/// element.
#[must_use = "result must be checked"]
pub(crate) fn encode_group_commitment_list(
    commitment_list: &[SigningCommitments],
) -> Result<Vec<u8>, CryptoError> {
    let mut encoded = Vec::with_capacity(commitment_list.len() * (SCALAR_LEN + 2 * ELEMENT_LEN));
    for commitment in commitment_list {
        encoded.extend_from_slice(&commitment.identifier().to_bytes());
        encoded.extend_from_slice(&serialize_element(&commitment.hiding())?);
        encoded.extend_from_slice(&serialize_element(&commitment.binding())?);
    }
    Ok(encoded)
}

/// A `(identifier, binding_factor)` entry of the binding-factor list
/// (RFC 9591 §4.4).
#[derive(Clone, Copy, Debug)]
pub(crate) struct BindingFactor {
    /// The participant identifier this binding factor belongs to.
    pub(crate) identifier: Identifier,
    /// The binding factor scalar `ρ_i`.
    pub(crate) factor: Scalar,
}

/// `compute_binding_factors(group_public_key, commitment_list, msg)`
/// (RFC 9591 §4.4).
///
/// For each participant, `ρ_i = H1(group_public_key_enc ‖ H4(msg) ‖
/// H5(encode_group_commitment_list) ‖ SerializeScalar(identifier))`.
/// `commitment_list` MUST be sorted ascending by identifier.
///
/// Returns [`CryptoError::InvalidKey`] if any commitment is the identity
/// element.
#[must_use = "result must be checked"]
pub(crate) fn compute_binding_factors(
    group_public_key: &EdwardsPoint,
    commitment_list: &[SigningCommitments],
    msg: &[u8],
) -> Result<Vec<BindingFactor>, CryptoError> {
    let group_public_key_enc = serialize_element(group_public_key)?;
    let msg_hash = h4(msg);
    let encoded_commitment_hash = h5(&encode_group_commitment_list(commitment_list)?);

    let mut rho_input_prefix =
        Vec::with_capacity(ELEMENT_LEN + msg_hash.len() + encoded_commitment_hash.len());
    rho_input_prefix.extend_from_slice(&group_public_key_enc);
    rho_input_prefix.extend_from_slice(&msg_hash);
    rho_input_prefix.extend_from_slice(&encoded_commitment_hash);

    let mut binding_factor_list = Vec::with_capacity(commitment_list.len());
    for commitment in commitment_list {
        let mut rho_input = rho_input_prefix.clone();
        rho_input.extend_from_slice(&commitment.identifier().to_bytes());
        binding_factor_list.push(BindingFactor {
            identifier: commitment.identifier(),
            factor: h1(&rho_input),
        });
    }
    Ok(binding_factor_list)
}

/// `binding_factor_for_participant(binding_factor_list, identifier)`
/// (RFC 9591 §4.3).
///
/// Returns [`CryptoError::BadInput`] ("invalid participant") if `identifier` is
/// not present in the list.
#[must_use = "result must be checked"]
pub(crate) fn binding_factor_for_participant(
    binding_factor_list: &[BindingFactor],
    identifier: Identifier,
) -> Result<Scalar, CryptoError> {
    binding_factor_list
        .iter()
        .find(|bf| bf.identifier == identifier)
        .map(|bf| bf.factor)
        .ok_or(CryptoError::BadInput)
}

/// `compute_group_commitment(commitment_list, binding_factor_list)`
/// (RFC 9591 §4.5).
///
/// Computes `R = Σ_i (D_i + ρ_i · E_i)` over the commitment list.
///
/// Returns [`CryptoError::BadInput`] if a commitment's identifier has no
/// matching binding factor.
#[must_use = "result must be checked"]
pub(crate) fn compute_group_commitment(
    commitment_list: &[SigningCommitments],
    binding_factor_list: &[BindingFactor],
) -> Result<EdwardsPoint, CryptoError> {
    let mut group_commitment = EdwardsPoint::default();
    for commitment in commitment_list {
        let binding_factor =
            binding_factor_for_participant(binding_factor_list, commitment.identifier())?;
        let binding = commitment.binding() * binding_factor;
        group_commitment += commitment.hiding() + binding;
    }
    Ok(group_commitment)
}

/// `compute_challenge(group_commitment, group_public_key, msg)`
/// (RFC 9591 §4.6).
///
/// Computes `c = H2(SerializeElement(R) ‖ SerializeElement(PK) ‖ msg)`. Because
/// `H2` is plain SHA-512 (no context), this is exactly the Ed25519 challenge.
///
/// Returns [`CryptoError::InvalidKey`] if `R` or `PK` is the identity element.
#[must_use = "result must be checked"]
pub(crate) fn compute_challenge(
    group_commitment: &EdwardsPoint,
    group_public_key: &EdwardsPoint,
    msg: &[u8],
) -> Result<Scalar, CryptoError> {
    let group_comm_enc = serialize_element(group_commitment)?;
    let group_public_key_enc = serialize_element(group_public_key)?;
    let mut challenge_input =
        Vec::with_capacity(group_comm_enc.len() + group_public_key_enc.len() + msg.len());
    challenge_input.extend_from_slice(&group_comm_enc);
    challenge_input.extend_from_slice(&group_public_key_enc);
    challenge_input.extend_from_slice(msg);
    Ok(h2(&challenge_input))
}

/// `derive_interpolating_value(L, x_i)` (RFC 9591 §4.2).
///
/// Computes the Lagrange coefficient `λ_i` for `x_i` over the signing subset
/// `L`, evaluated at `0`:
/// `λ_i = Π_{x_j ∈ L, x_j ≠ x_i} x_j / (x_j − x_i)`.
///
/// Returns [`CryptoError::BadInput`] ("invalid parameters") if `x_i ∉ L`, if any
/// identifier appears more than once, or if the denominator is non-invertible.
#[must_use = "result must be checked"]
pub(crate) fn derive_interpolating_value(
    participants: &[Identifier],
    x_i: Identifier,
) -> Result<Scalar, CryptoError> {
    if !participants.contains(&x_i) {
        return Err(CryptoError::BadInput);
    }
    for (idx, p) in participants.iter().enumerate() {
        if participants[idx + 1..].contains(p) {
            return Err(CryptoError::BadInput);
        }
    }

    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    let xi_scalar = x_i.as_scalar();
    for x_j in participants {
        if *x_j == x_i {
            continue;
        }
        let xj_scalar = x_j.as_scalar();
        numerator *= xj_scalar;
        denominator *= xj_scalar - xi_scalar;
    }

    if denominator == Scalar::ZERO {
        return Err(CryptoError::BadInput);
    }
    Ok(numerator * denominator.invert())
}

/// Sort a slice of [`SigningCommitments`] ascending by identifier (treating the
/// 32-byte little-endian identifier encoding as the ordering key) and check
/// that all identifiers are distinct.
///
/// RFC 9591 requires `commitment_list` to be sorted ascending by identifier;
/// this helper lets callers pass commitments in any order. Returns
/// [`CryptoError::BadInput`] if two commitments share an identifier.
#[must_use = "result must be checked"]
pub fn sort_commitments(
    commitments: &[SigningCommitments],
) -> Result<Vec<SigningCommitments>, CryptoError> {
    let mut sorted = commitments.to_vec();
    sorted.sort_by_key(|c| c.identifier().to_bytes());
    for window in sorted.windows(2) {
        if window[0].identifier() == window[1].identifier() {
            return Err(CryptoError::BadInput);
        }
    }
    Ok(sorted)
}
