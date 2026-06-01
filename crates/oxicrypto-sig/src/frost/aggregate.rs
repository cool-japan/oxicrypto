#![forbid(unsafe_code)]

//! FROST signature-share aggregation and signature verification
//! (RFC 9591 §5.3, §6.1).
//!
//! The Coordinator sums the participants' signature shares into the final
//! Schnorr signature `(R, z)`, which is encoded as the 64 bytes
//! `SerializeElement(R) ‖ SerializeScalar(z)`. The resulting signature verifies
//! both under the FROST group equation and — because `H2` is plain SHA-512 —
//! under standard Ed25519 verification (RFC 8032 §5.1.7).

use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use oxicrypto_core::CryptoError;

use super::round1::SigningCommitments;
use super::round2::SignatureShare;
use super::{
    compute_binding_factors, compute_challenge, compute_group_commitment, deserialize_element,
    deserialize_scalar, scalar_base_mult, serialize_element, serialize_scalar, ELEMENT_LEN,
    SIGNATURE_LEN,
};

/// A FROST Schnorr signature `(R, z)` (RFC 9591 §5.3).
///
/// Encoded as the 64 bytes `SerializeElement(R) ‖ SerializeScalar(z)`
/// (RFC 9591 Appendix A); this is byte-identical to a standard Ed25519
/// signature.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// The group commitment `R`, an [`EdwardsPoint`].
    r: EdwardsPoint,
    /// The aggregated response scalar `z`.
    z: Scalar,
}

impl Signature {
    /// Construct a signature from its constituent `(R, z)` values.
    #[must_use]
    pub fn new(r: EdwardsPoint, z: Scalar) -> Self {
        Self { r, z }
    }

    /// The group commitment `R`.
    #[must_use]
    pub fn r(&self) -> EdwardsPoint {
        self.r
    }

    /// The response scalar `z`.
    #[must_use]
    pub fn z(&self) -> Scalar {
        self.z
    }

    /// Encode the signature as 64 bytes `SerializeElement(R) ‖ SerializeScalar(z)`.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `R` is the identity element.
    #[must_use = "result must be checked"]
    pub fn to_bytes(&self) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        let r_enc = serialize_element(&self.r)?;
        let z_enc = serialize_scalar(&self.z);
        let mut out = [0u8; SIGNATURE_LEN];
        out[..ELEMENT_LEN].copy_from_slice(&r_enc);
        out[ELEMENT_LEN..].copy_from_slice(&z_enc);
        Ok(out)
    }

    /// Decode a signature from the 64-byte encoding `R ‖ z`.
    ///
    /// Returns [`CryptoError::InvalidTag`] on a wrong length, or if `R` / `z`
    /// is not a valid encoding.
    #[must_use = "result must be checked"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::InvalidTag);
        }
        let r = deserialize_element(&bytes[..ELEMENT_LEN]).map_err(|_| CryptoError::InvalidTag)?;
        let z = deserialize_scalar(&bytes[ELEMENT_LEN..]).map_err(|_| CryptoError::InvalidTag)?;
        Ok(Self { r, z })
    }
}

/// `aggregate(commitment_list, msg, group_public_key, sig_shares)` — combine
/// signature shares into the final signature (RFC 9591 §5.3).
///
/// Recomputes the group commitment `R` from `commitment_list` and the message,
/// then sums the shares: `z = Σ z_i`. Returns the signature `(R, z)`.
///
/// `commitment_list` MUST be sorted ascending by identifier (use
/// [`super::sort_commitments`]). This does *not* itself verify the signature —
/// callers SHOULD call [`verify_signature`] before publishing.
///
/// Returns [`CryptoError::InvalidKey`] if a commitment or the public key is the
/// identity element, or [`CryptoError::BadInput`] if the binding factors cannot
/// be resolved.
#[must_use = "the aggregated signature must be used"]
pub fn aggregate(
    commitment_list: &[SigningCommitments],
    msg: &[u8],
    group_public_key: &EdwardsPoint,
    sig_shares: &[SignatureShare],
) -> Result<Signature, CryptoError> {
    let binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)?;
    let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list)?;

    let mut z = Scalar::ZERO;
    for share in sig_shares {
        z += share.value();
    }

    Ok(Signature::new(group_commitment, z))
}

/// Verify a FROST signature `(R, z)` over `msg` under the group public key
/// (RFC 9591 §6.1).
///
/// This performs **both** checks for defense in depth:
///
/// 1. The FROST group equation `z · B == R + c · PK`, where
///    `c = H2(R ‖ PK ‖ msg)`.
/// 2. Standard Ed25519 verification (RFC 8032 §5.1.7) of the 64-byte encoding
///    `R ‖ z` against the encoded group public key, confirming the aggregate is
///    a valid ordinary Ed25519 signature.
///
/// Returns `Ok(())` if both checks pass, [`CryptoError::Sign`] if either fails,
/// or [`CryptoError::InvalidKey`] if `R` or `PK` is the identity element.
#[must_use = "verification result must be checked"]
pub fn verify_signature(
    signature: &Signature,
    msg: &[u8],
    group_public_key: &EdwardsPoint,
) -> Result<(), CryptoError> {
    // (1) FROST group equation: z·B == R + c·PK.
    let challenge = compute_challenge(&signature.r(), group_public_key, msg)?;
    let lhs = scalar_base_mult(&signature.z());
    let rhs = signature.r() + (*group_public_key * challenge);
    if lhs != rhs {
        return Err(CryptoError::Sign);
    }

    // (2) Cross-check against standard Ed25519 verification.
    verify_ed25519(signature, msg, group_public_key)
}

/// Verify the signature as an ordinary Ed25519 signature via `ed25519-dalek`.
///
/// Encodes the group public key and the signature, then runs strict Ed25519
/// verification. Returns [`CryptoError::InvalidKey`] if `PK` / `R` is the
/// identity element or the public key is malformed, and [`CryptoError::Sign`]
/// on verification failure.
fn verify_ed25519(
    signature: &Signature,
    msg: &[u8],
    group_public_key: &EdwardsPoint,
) -> Result<(), CryptoError> {
    let pk_bytes = serialize_element(group_public_key)?;
    let verifying_key =
        Ed25519VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let sig_bytes = signature.to_bytes()?;
    let ed_sig = Ed25519Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(msg, &ed_sig)
        .map_err(|_| CryptoError::Sign)
}
