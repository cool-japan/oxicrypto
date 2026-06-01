#![forbid(unsafe_code)]

//! FROST round one — commitment (RFC 9591 §5.1).
//!
//! Each signing participant generates a one-time `(hiding, binding)` nonce pair
//! via `nonce_generate` and publishes the corresponding commitments
//! `D_i = d_i · B` and `E_i = e_i · B`. The secret nonces are retained locally
//! for round two and MUST NOT be reused.

use curve25519_dalek::{EdwardsPoint, Scalar};
use oxicrypto_core::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    deserialize_element, h3, scalar_base_mult, serialize_element, serialize_scalar, Identifier,
    ELEMENT_LEN,
};

/// A participant's one-time secret nonce pair `(hiding_nonce, binding_nonce)`
/// generated in round one (RFC 9591 §5.1). Both scalars are zeroized on drop.
///
/// These values are secret and MUST NOT be shared or reused across signing
/// sessions. They are consumed by [`super::round2::sign`].
#[derive(Clone)]
pub struct SigningNonces {
    identifier: Identifier,
    hiding_nonce: Scalar,
    binding_nonce: Scalar,
}

impl SigningNonces {
    /// The participant identifier these nonces belong to.
    #[must_use]
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The hiding nonce `d_i`.
    #[must_use]
    pub fn hiding_nonce(&self) -> Scalar {
        self.hiding_nonce
    }

    /// The binding nonce `e_i`.
    #[must_use]
    pub fn binding_nonce(&self) -> Scalar {
        self.binding_nonce
    }

    /// The public commitments `(D_i, E_i)` corresponding to these nonces.
    #[must_use]
    pub fn commitments(&self) -> SigningCommitments {
        SigningCommitments {
            identifier: self.identifier,
            hiding: scalar_base_mult(&self.hiding_nonce),
            binding: scalar_base_mult(&self.binding_nonce),
        }
    }
}

impl Drop for SigningNonces {
    fn drop(&mut self) {
        self.hiding_nonce.zeroize();
        self.binding_nonce.zeroize();
    }
}

impl ZeroizeOnDrop for SigningNonces {}

/// A participant's public commitment pair `(D_i, E_i)` published in round one
/// (RFC 9591 §5.1), tagged with its identifier.
#[derive(Clone, Copy, Debug)]
pub struct SigningCommitments {
    identifier: Identifier,
    hiding: EdwardsPoint,
    binding: EdwardsPoint,
}

impl SigningCommitments {
    /// Construct commitments from an identifier and the two commitment points.
    #[must_use]
    pub fn new(identifier: Identifier, hiding: EdwardsPoint, binding: EdwardsPoint) -> Self {
        Self {
            identifier,
            hiding,
            binding,
        }
    }

    /// Parse commitments from the 32-byte compressed encodings of `D_i` and
    /// `E_i`.
    ///
    /// Returns [`CryptoError::InvalidKey`] if either encoding is not a valid
    /// non-identity prime-order point.
    #[must_use = "result must be checked"]
    pub fn from_bytes(
        identifier: Identifier,
        hiding_bytes: &[u8],
        binding_bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            identifier,
            hiding: deserialize_element(hiding_bytes)?,
            binding: deserialize_element(binding_bytes)?,
        })
    }

    /// The participant identifier.
    #[must_use]
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The hiding-nonce commitment `D_i`.
    #[must_use]
    pub fn hiding(&self) -> EdwardsPoint {
        self.hiding
    }

    /// The binding-nonce commitment `E_i`.
    #[must_use]
    pub fn binding(&self) -> EdwardsPoint {
        self.binding
    }

    /// The 32-byte compressed encoding of the hiding-nonce commitment `D_i`.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `D_i` is the identity element.
    #[must_use = "result must be checked"]
    pub fn hiding_bytes(&self) -> Result<[u8; ELEMENT_LEN], CryptoError> {
        serialize_element(&self.hiding)
    }

    /// The 32-byte compressed encoding of the binding-nonce commitment `E_i`.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `E_i` is the identity element.
    #[must_use = "result must be checked"]
    pub fn binding_bytes(&self) -> Result<[u8; ELEMENT_LEN], CryptoError> {
        serialize_element(&self.binding)
    }
}

/// `nonce_generate(secret)` — derive a nonce scalar from 32 bytes of fresh
/// randomness and the secret share (RFC 9591 §4.1).
///
/// `nonce = H3(random_bytes ‖ SerializeScalar(secret))`.
#[must_use]
fn nonce_generate(random_bytes: &[u8; 32], secret: &Scalar) -> Scalar {
    let secret_enc = serialize_scalar(secret);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(random_bytes);
    input[32..].copy_from_slice(&secret_enc);
    let nonce = h3(&input);
    input.zeroize();
    nonce
}

/// `commit(sk_i)` with **caller-supplied** nonce randomness (RFC 9591 §5.1).
///
/// This is the derandomized seam used to reproduce the RFC 9591 test vectors:
/// the caller injects the exact `hiding_nonce_randomness` and
/// `binding_nonce_randomness` from the vector. Production code SHOULD use
/// [`commit`], which samples fresh randomness from a CSPRNG.
///
/// Returns the secret [`SigningNonces`] (kept locally for round two); the
/// matching public [`SigningCommitments`] are obtained via
/// [`SigningNonces::commitments`].
#[must_use = "signing nonces must be retained for round two"]
pub(crate) fn commit_with_randomness(
    identifier: Identifier,
    secret: &Scalar,
    hiding_randomness: &[u8; 32],
    binding_randomness: &[u8; 32],
) -> SigningNonces {
    SigningNonces {
        identifier,
        hiding_nonce: nonce_generate(hiding_randomness, secret),
        binding_nonce: nonce_generate(binding_randomness, secret),
    }
}

/// `commit(sk_i)` — round-one commitment generation (RFC 9591 §5.1).
///
/// Samples two independent 32-byte random values from `rng` and derives the
/// hiding and binding nonces from them and the secret share. Returns the secret
/// [`SigningNonces`]; obtain the public commitments via
/// [`SigningNonces::commitments`].
///
/// Returns [`CryptoError::Rng`] if the RNG fails.
#[must_use = "signing nonces must be retained for round two"]
pub fn commit<R: rand_core::TryCryptoRng + ?Sized>(
    rng: &mut R,
    identifier: Identifier,
    secret: &Scalar,
) -> Result<SigningNonces, CryptoError> {
    let mut hiding_randomness = [0u8; 32];
    let mut binding_randomness = [0u8; 32];
    rng.try_fill_bytes(&mut hiding_randomness)
        .map_err(|_| CryptoError::Rng)?;
    rng.try_fill_bytes(&mut binding_randomness)
        .map_err(|_| CryptoError::Rng)?;

    let nonces =
        commit_with_randomness(identifier, secret, &hiding_randomness, &binding_randomness);
    hiding_randomness.zeroize();
    binding_randomness.zeroize();
    Ok(nonces)
}
