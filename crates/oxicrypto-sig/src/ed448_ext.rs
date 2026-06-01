#![forbid(unsafe_code)]

//! Ed448ph (pre-hash) and Ed448ctx (context) signature variants per RFC 8032 §5.2.
//!
//! # Ed448ph
//!
//! Ed448ph signs over `dom4(phflag=1, ctx_len, ctx) ‖ SHAKE256(msg, 64)`.
//! This is the prehash variant — useful for signing large messages where you
//! want to hash the message separately.
//!
//! # Ed448ctx
//!
//! Ed448ctx uses a domain-separation context string (up to 255 bytes) for
//! the standard (non-prehashed) Ed448. Useful for protocol-level separation.

// We must use the sha3 re-exported by ed448-goldilocks (sha3 0.11) to ensure
// the Shake256 type matches what PreHasherXof expects. Using the workspace
// sha3 0.12 would produce a different (incompatible) Shake256 type.
use ed448_goldilocks::sha3::digest::Update;
use ed448_goldilocks::{
    sha3::Shake256, EdwardsScalarBytes, PreHasherXof, Signature, SigningKey, VerifyingKey,
};
use oxicrypto_core::{CryptoError, Vec};

// ── Ed448ph ───────────────────────────────────────────────────────────────────

/// Sign `message` using Ed448ph (pre-hashed Ed448 per RFC 8032 §5.2.5).
///
/// `sk` must be 57 bytes (raw seed). `context` is optional and up to 255 bytes.
///
/// Internally hashes `message` with SHAKE-256 (64-byte output) before signing,
/// producing a 114-byte signature.
#[must_use = "signature result must be checked"]
pub fn ed448ph_sign(
    sk: &[u8],
    message: &[u8],
    context: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let sk_bytes: [u8; 57] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let scalar = EdwardsScalarBytes::from(sk_bytes);
    let signing_key = SigningKey::from(scalar);

    // Feed message into SHAKE-256, then wrap in PreHasherXof.
    // PreHasherXof::new() calls finalize_xof() internally.
    let mut hasher = Shake256::default();
    hasher.update(message);
    let prehash = PreHasherXof::<Shake256>::new(hasher);

    let sig: Signature = signing_key
        .sign_prehashed(context, prehash)
        .map_err(|_| CryptoError::Sign)?;

    Ok(sig.to_bytes().to_vec())
}

/// Verify an Ed448ph signature per RFC 8032 §5.2.5.
///
/// `pk` must be 57 bytes (compressed public key), `sig` must be 114 bytes.
/// `context` must match what was used during signing.
#[must_use = "verification result must be checked"]
pub fn ed448ph_verify(
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
    context: Option<&[u8]>,
) -> Result<(), CryptoError> {
    let pk_bytes: &[u8; 57] = pk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let sig_bytes: [u8; 114] = sig.try_into().map_err(|_| CryptoError::InvalidTag)?;

    let verifying_key = VerifyingKey::from_bytes(pk_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Reconstruct the SHAKE-256 pre-hasher for verification
    let mut hasher = Shake256::default();
    hasher.update(message);
    let prehash = PreHasherXof::<Shake256>::new(hasher);

    verifying_key
        .verify_prehashed(&signature, context, prehash)
        .map_err(|_| CryptoError::InvalidTag)
}

// ── Ed448ctx ──────────────────────────────────────────────────────────────────

/// Sign `message` using Ed448 with a context string (non-prehashed).
///
/// `sk` must be 57 bytes (raw seed). `context` provides domain separation
/// and must be at most 255 bytes. Returns a 114-byte signature.
#[must_use = "signature result must be checked"]
pub fn ed448ctx_sign(sk: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    let sk_bytes: [u8; 57] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let scalar = EdwardsScalarBytes::from(sk_bytes);
    let signing_key = SigningKey::from(scalar);

    let sig: Signature = signing_key
        .sign_ctx(context, message)
        .map_err(|_| CryptoError::Sign)?;

    Ok(sig.to_bytes().to_vec())
}

/// Verify an Ed448 context signature.
///
/// `pk` must be 57 bytes, `sig` must be 114 bytes.
/// `context` must match what was used during signing.
#[must_use = "verification result must be checked"]
pub fn ed448ctx_verify(
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
    context: &[u8],
) -> Result<(), CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    let pk_bytes: &[u8; 57] = pk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let sig_bytes: [u8; 114] = sig.try_into().map_err(|_| CryptoError::InvalidTag)?;

    let verifying_key = VerifyingKey::from_bytes(pk_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify_ctx(&signature, context, message)
        .map_err(|_| CryptoError::InvalidTag)
}
