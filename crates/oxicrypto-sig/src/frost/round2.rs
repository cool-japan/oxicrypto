#![forbid(unsafe_code)]

//! FROST round two — signature share generation and verification
//! (RFC 9591 §5.2, §5.3).
//!
//! Given the message and the sorted list of all participants' commitments, each
//! signer produces a signature share
//! `z_i = d_i + (e_i · ρ_i) + (λ_i · s_i · c)`. The Coordinator can verify each
//! share via [`verify_signature_share`] before aggregating.

use curve25519_dalek::{EdwardsPoint, Scalar};
use oxicrypto_core::CryptoError;

use super::keygen::KeyPackage;
use super::round1::{SigningCommitments, SigningNonces};
use super::{
    binding_factor_for_participant, compute_binding_factors, compute_challenge,
    compute_group_commitment, derive_interpolating_value, deserialize_scalar, scalar_base_mult,
    serialize_scalar, Identifier, SCALAR_LEN,
};
use oxicrypto_core::Vec;

/// A participant's signature share `z_i` produced in round two
/// (RFC 9591 §5.2), tagged with its identifier.
#[derive(Clone, Copy, Debug)]
pub struct SignatureShare {
    identifier: Identifier,
    value: Scalar,
}

impl SignatureShare {
    /// Construct a signature share from an identifier and scalar value.
    #[must_use]
    pub fn new(identifier: Identifier, value: Scalar) -> Self {
        Self { identifier, value }
    }

    /// Parse a signature share from its identifier and the 32-byte little-endian
    /// canonical encoding of the share scalar.
    ///
    /// Returns [`CryptoError::InvalidTag`] if `value_bytes` is not a canonical
    /// scalar.
    #[must_use = "result must be checked"]
    pub fn from_bytes(identifier: Identifier, value_bytes: &[u8]) -> Result<Self, CryptoError> {
        let value = deserialize_scalar(value_bytes).map_err(|_| CryptoError::InvalidTag)?;
        Ok(Self { identifier, value })
    }

    /// The participant identifier.
    #[must_use]
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The signature share scalar `z_i`.
    #[must_use]
    pub fn value(&self) -> Scalar {
        self.value
    }

    /// The 32-byte little-endian encoding of the signature share `z_i`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SCALAR_LEN] {
        serialize_scalar(&self.value)
    }
}

/// Extract the sorted list of participant identifiers from a commitment list
/// (`participants_from_commitment_list`, RFC 9591 §4.3).
#[must_use]
fn participants_from_commitment_list(commitment_list: &[SigningCommitments]) -> Vec<Identifier> {
    commitment_list.iter().map(|c| c.identifier()).collect()
}

/// `sign(identifier, sk_i, group_public_key, nonce_i, msg, commitment_list)`
/// — produce this participant's signature share (RFC 9591 §5.2).
///
/// Computes the binding factors over `commitment_list`, the group commitment
/// `R`, the interpolating value `λ_i`, and the challenge `c`, then returns
/// `z_i = d_i + (e_i · ρ_i) + (λ_i · s_i · c)`.
///
/// `commitment_list` MUST be sorted ascending by identifier (use
/// [`super::sort_commitments`]) and MUST include this participant's own
/// commitments matching `nonces`.
///
/// Returns [`CryptoError::BadInput`] if `nonces` and `key_package` disagree on
/// the identifier, if this participant's commitments are absent from
/// `commitment_list`, or if the interpolating value cannot be derived;
/// [`CryptoError::InvalidKey`] if a commitment or public key is the identity
/// element.
#[must_use = "the signature share must be sent to the coordinator"]
pub fn sign(
    key_package: &KeyPackage,
    nonces: &SigningNonces,
    msg: &[u8],
    commitment_list: &[SigningCommitments],
) -> Result<SignatureShare, CryptoError> {
    let identifier = key_package.identifier();
    if nonces.identifier() != identifier {
        return Err(CryptoError::BadInput);
    }

    // The participant MUST appear in the commitment list (RFC 9591 §5.2).
    if !commitment_list.iter().any(|c| c.identifier() == identifier) {
        return Err(CryptoError::BadInput);
    }

    let group_public_key = key_package.group_public_key();

    // Binding factors and this participant's binding factor.
    let binding_factor_list = compute_binding_factors(&group_public_key, commitment_list, msg)?;
    let binding_factor = binding_factor_for_participant(&binding_factor_list, identifier)?;

    // Group commitment R = Σ (D_i + ρ_i·E_i).
    let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list)?;

    // Interpolating value λ_i over the signing subset.
    let participant_list = participants_from_commitment_list(commitment_list);
    let lambda_i = derive_interpolating_value(&participant_list, identifier)?;

    // Per-message challenge c = H2(R ‖ PK ‖ msg).
    let challenge = compute_challenge(&group_commitment, &group_public_key, msg)?;

    // z_i = d_i + (e_i · ρ_i) + (λ_i · s_i · c).
    let s_i = key_package.secret_share().value();
    let sig_share = nonces.hiding_nonce()
        + (nonces.binding_nonce() * binding_factor)
        + (lambda_i * s_i * challenge);

    Ok(SignatureShare::new(identifier, sig_share))
}

/// `verify_signature_share(identifier, PK_i, comm_i, sig_share_i,
/// commitment_list, group_public_key, msg)` (RFC 9591 §5.3).
///
/// Checks `z_i · B == (D_i + ρ_i · E_i) + (λ_i · c) · PK_i`.
///
/// `commitment_list` MUST be sorted ascending by identifier and contain
/// `comm_i`. Returns `Ok(())` if the share is valid, [`CryptoError::Sign`] if
/// the relation does not hold, [`CryptoError::BadInput`] for missing
/// participants / interpolation failures, or [`CryptoError::InvalidKey`] for an
/// identity-element commitment or public key.
#[must_use = "verification result must be checked"]
pub fn verify_signature_share(
    public_share: &EdwardsPoint,
    comm_i: &SigningCommitments,
    sig_share_i: &SignatureShare,
    commitment_list: &[SigningCommitments],
    group_public_key: &EdwardsPoint,
    msg: &[u8],
) -> Result<(), CryptoError> {
    let identifier = sig_share_i.identifier();

    let binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)?;
    let binding_factor = binding_factor_for_participant(&binding_factor_list, identifier)?;
    let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list)?;

    // comm_share = D_i + ρ_i·E_i.
    let comm_share = comm_i.hiding() + (comm_i.binding() * binding_factor);

    let challenge = compute_challenge(&group_commitment, group_public_key, msg)?;

    let participant_list = participants_from_commitment_list(commitment_list);
    let lambda_i = derive_interpolating_value(&participant_list, identifier)?;

    // l = z_i·B ; r = comm_share + (c·λ_i)·PK_i.
    let l = scalar_base_mult(&sig_share_i.value());
    let r = comm_share + (*public_share * (challenge * lambda_i));

    if l == r {
        Ok(())
    } else {
        Err(CryptoError::Sign)
    }
}
