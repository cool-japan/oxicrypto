#![forbid(unsafe_code)]

//! Trusted-dealer key generation for FROST(Ed25519, SHA-512) (RFC 9591 §C.1).
//!
//! A trusted dealer holds the group secret `s` (a [`Scalar`]), samples a degree
//! `t−1` polynomial `f` with `f(0) = s`, and distributes the shares
//! `s_i = f(i)` to participants `i = 1 … n`. The group public key is
//! `PK = s · B` and each participant's public-key share is `PK_i = s_i · B`.
//!
//! Two constructors are provided:
//!
//! * [`trusted_dealer_keygen`] — samples the polynomial coefficients from a
//!   supplied RNG (the production path).
//! * [`trusted_dealer_keygen_with_coefficients`] — accepts the non-constant
//!   coefficients explicitly (the derandomized path, for reproducing the
//!   RFC 9591 test vectors).

use curve25519_dalek::{EdwardsPoint, Scalar};
use oxicrypto_core::{CryptoError, Vec};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    deserialize_scalar, scalar_base_mult, serialize_element, serialize_scalar, Identifier,
    SCALAR_LEN,
};

/// One participant's secret signing-key share `(identifier, s_i)`
/// (RFC 9591 §5). The scalar is zeroized on drop.
#[derive(Clone)]
pub struct SecretShare {
    identifier: Identifier,
    value: Scalar,
}

impl SecretShare {
    /// Construct a secret share from an identifier and scalar value.
    #[must_use]
    pub fn new(identifier: Identifier, value: Scalar) -> Self {
        Self { identifier, value }
    }

    /// Parse a secret share from its identifier and the 32-byte little-endian
    /// canonical encoding of the share scalar.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `value_bytes` is not a canonical
    /// scalar.
    #[must_use = "result must be checked"]
    pub fn from_bytes(identifier: Identifier, value_bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            identifier,
            value: deserialize_scalar(value_bytes)?,
        })
    }

    /// The participant identifier of this share.
    #[must_use]
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The secret share scalar `s_i`.
    #[must_use]
    pub fn value(&self) -> Scalar {
        self.value
    }

    /// The 32-byte little-endian encoding of the share scalar `s_i`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SCALAR_LEN] {
        serialize_scalar(&self.value)
    }

    /// Derive the per-participant public-key share `PK_i = s_i · B`.
    #[must_use]
    pub fn public_share(&self) -> EdwardsPoint {
        scalar_base_mult(&self.value)
    }
}

impl Drop for SecretShare {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl ZeroizeOnDrop for SecretShare {}

/// A participant's long-term key material: its secret share plus the public
/// information needed to sign (RFC 9591 §5).
///
/// This bundles the [`SecretShare`] with the participant's public-key share
/// `PK_i` and the group public key `PK`.
#[derive(Clone)]
pub struct KeyPackage {
    secret_share: SecretShare,
    public_share: EdwardsPoint,
    group_public_key: EdwardsPoint,
}

impl KeyPackage {
    /// Assemble a key package from a secret share and the group public key,
    /// deriving the public-key share `PK_i = s_i · B`.
    #[must_use]
    pub fn new(secret_share: SecretShare, group_public_key: EdwardsPoint) -> Self {
        let public_share = secret_share.public_share();
        Self {
            secret_share,
            public_share,
            group_public_key,
        }
    }

    /// The participant identifier.
    #[must_use]
    pub fn identifier(&self) -> Identifier {
        self.secret_share.identifier()
    }

    /// The secret share `s_i`.
    #[must_use]
    pub fn secret_share(&self) -> &SecretShare {
        &self.secret_share
    }

    /// The participant public-key share `PK_i`.
    #[must_use]
    pub fn public_share(&self) -> EdwardsPoint {
        self.public_share
    }

    /// The group public key `PK`.
    #[must_use]
    pub fn group_public_key(&self) -> EdwardsPoint {
        self.group_public_key
    }
}

/// The public output of key generation shared with all participants and the
/// Coordinator (RFC 9591 §5 "group info").
#[derive(Clone, Debug)]
pub struct PublicKeyPackage {
    group_public_key: EdwardsPoint,
    public_shares: Vec<(Identifier, EdwardsPoint)>,
}

impl PublicKeyPackage {
    /// The group public key `PK`.
    #[must_use]
    pub fn group_public_key(&self) -> EdwardsPoint {
        self.group_public_key
    }

    /// The 32-byte compressed encoding of the group public key `PK`.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `PK` is the identity element.
    #[must_use = "result must be checked"]
    pub fn group_public_key_bytes(&self) -> Result<[u8; 32], CryptoError> {
        serialize_element(&self.group_public_key)
    }

    /// The list of per-participant public-key shares `(identifier, PK_i)`.
    #[must_use]
    pub fn public_shares(&self) -> &[(Identifier, EdwardsPoint)] {
        &self.public_shares
    }

    /// Look up the public-key share `PK_i` for `identifier`.
    ///
    /// Returns [`CryptoError::BadInput`] if `identifier` is unknown.
    #[must_use = "result must be checked"]
    pub fn public_share(&self, identifier: Identifier) -> Result<EdwardsPoint, CryptoError> {
        self.public_shares
            .iter()
            .find(|(id, _)| *id == identifier)
            .map(|(_, pk)| *pk)
            .ok_or(CryptoError::BadInput)
    }
}

/// A degree `t−1` polynomial over [`Scalar`] with the secret as constant term;
/// coefficients are zeroized on drop.
struct Polynomial {
    /// Coefficients `[a_0, a_1, …, a_{t-1}]`, constant term first.
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Build the polynomial `f(x) = s + a_1 x + … + a_{t-1} x^{t-1}` from the
    /// secret `s` and the `t−1` non-constant coefficients.
    fn new(secret: Scalar, non_constant: &[Scalar]) -> Self {
        let mut coefficients = Vec::with_capacity(non_constant.len() + 1);
        coefficients.push(secret);
        coefficients.extend_from_slice(non_constant);
        Self { coefficients }
    }

    /// `polynomial_evaluate(x, coeffs)` via Horner's method (RFC 9591 §C.1.1).
    fn evaluate(&self, x: Scalar) -> Scalar {
        let mut value = Scalar::ZERO;
        for coeff in self.coefficients.iter().rev() {
            value *= x;
            value += coeff;
        }
        value
    }
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        for coeff in &mut self.coefficients {
            coeff.zeroize();
        }
    }
}

/// Validate `(max_participants, min_participants)` per RFC 9591 §5.
///
/// Requires `1 ≤ min ≤ max` and `max < 2^16` (so identifiers `1..=max` fit a
/// `u16`, far below the group order). Returns [`CryptoError::BadInput`]
/// otherwise.
fn check_params(max_participants: u16, min_participants: u16) -> Result<(), CryptoError> {
    if min_participants == 0 || max_participants == 0 || min_participants > max_participants {
        return Err(CryptoError::BadInput);
    }
    Ok(())
}

/// Shard `secret` into `max_participants` shares using the supplied polynomial,
/// and assemble the public outputs. Shared by both keygen constructors.
fn shard(
    secret: Scalar,
    polynomial: &Polynomial,
    max_participants: u16,
) -> Result<(Vec<SecretShare>, PublicKeyPackage), CryptoError> {
    let group_public_key = scalar_base_mult(&secret);

    let mut shares = Vec::with_capacity(usize::from(max_participants));
    let mut public_shares = Vec::with_capacity(usize::from(max_participants));
    for index in 1..=max_participants {
        let identifier = Identifier::new(index)?;
        let value = polynomial.evaluate(identifier.as_scalar());
        let share = SecretShare::new(identifier, value);
        public_shares.push((identifier, share.public_share()));
        shares.push(share);
    }

    Ok((
        shares,
        PublicKeyPackage {
            group_public_key,
            public_shares,
        },
    ))
}

/// Trusted-dealer key generation with **explicit** polynomial coefficients
/// (RFC 9591 §C.1, derandomized).
///
/// `secret` is the group signing key `s`. `non_constant_coefficients` are the
/// `t−1` coefficients `[a_1, …, a_{t-1}]` of the sharing polynomial `f`, where
/// `f(0) = s` and `t = min_participants`; thus `non_constant_coefficients.len()`
/// MUST equal `min_participants − 1`. This is the path used to reproduce the
/// RFC 9591 test vectors.
///
/// Returns the `max_participants` secret shares (identifiers `1..=n`) and the
/// public key package `{PK, [(i, PK_i)]}`.
///
/// Returns [`CryptoError::BadInput`] if the participant counts are invalid
/// (e.g., `min_participants > max_participants`, or either is zero) or if the coefficient count does not match
/// `min_participants − 1`.
#[must_use = "key material must be used"]
pub fn trusted_dealer_keygen_with_coefficients(
    secret: Scalar,
    non_constant_coefficients: &[Scalar],
    max_participants: u16,
    min_participants: u16,
) -> Result<(Vec<SecretShare>, PublicKeyPackage), CryptoError> {
    check_params(max_participants, min_participants)?;
    if non_constant_coefficients.len() != usize::from(min_participants - 1) {
        return Err(CryptoError::BadInput);
    }
    let polynomial = Polynomial::new(secret, non_constant_coefficients);
    shard(secret, &polynomial, max_participants)
}

/// Trusted-dealer key generation that samples the polynomial coefficients and
/// the group secret from a supplied RNG (RFC 9591 §C, production path).
///
/// Produces a fresh group secret `s` and a degree `t−1` polynomial, then shards
/// `s` into `max_participants` shares (identifiers `1..=n`), returning them with
/// the public key package. `t = min_participants`.
///
/// Each sampled scalar is drawn uniformly via `Scalar::from_bytes_mod_order_wide`
/// over 64 fresh random bytes (RFC 9591 Appendix D guidance).
///
/// Returns [`CryptoError::BadInput`] for invalid participant counts, or
/// [`CryptoError::Rng`] if the RNG fails.
#[must_use = "key material must be used"]
pub fn trusted_dealer_keygen<R: rand_core::TryCryptoRng + ?Sized>(
    rng: &mut R,
    max_participants: u16,
    min_participants: u16,
) -> Result<(Vec<SecretShare>, PublicKeyPackage), CryptoError> {
    check_params(max_participants, min_participants)?;

    let secret = random_scalar(rng)?;
    let mut non_constant = Vec::with_capacity(usize::from(min_participants - 1));
    for _ in 0..(min_participants - 1) {
        non_constant.push(random_scalar(rng)?);
    }

    let polynomial = Polynomial::new(secret, &non_constant);
    let result = shard(secret, &polynomial, max_participants);
    non_constant.zeroize();
    result
}

/// Sample a uniformly random [`Scalar`] from `rng` using 64 fresh random bytes
/// reduced mod `ℓ` (`G.RandomScalar`, RFC 9591 Appendix D).
///
/// Returns [`CryptoError::Rng`] if the RNG fails.
fn random_scalar<R: rand_core::TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Scalar, CryptoError> {
    let mut wide = [0u8; 64];
    rng.try_fill_bytes(&mut wide)
        .map_err(|_| CryptoError::Rng)?;
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    Ok(scalar)
}
