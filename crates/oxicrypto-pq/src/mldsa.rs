//! ML-DSA (FIPS 204) post-quantum digital signature algorithm.
//!
//! Provides three parameter sets:
//!
//! | Type | Security | Public key | Signature |
//! |------|----------|-----------|-----------|
//! | [`MlDsa44`] | Category 2 (≈128-bit sym) | 1312 B | 2420 B |
//! | [`MlDsa65`] | Category 3 (≈192-bit sym) | 1952 B | 3309 B |
//! | [`MlDsa87`] | Category 5 (≈256-bit sym) | 2592 B | 4627 B |
//!
//! # Usage
//!
//! ```rust
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//! use oxicrypto_pq::mldsa::MlDsa65;
//!
//! let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
//! let (sk, vk) = MlDsa65::generate(&mut rng);
//! let sig = sk.sign(b"hello world").unwrap();
//! vk.verify(b"hello world", &sig).unwrap();
//! ```

use core::fmt;
use ml_dsa::signature::{Signer as _, Verifier as _};
use ml_dsa::{
    Generate, KeyExport, Keypair, MlDsa44 as MlDsa44Params, MlDsa65 as MlDsa65Params,
    MlDsa87 as MlDsa87Params, Seed, Signature, SigningKey, VerifyingKey,
};
use oxicrypto_core::CryptoError;
use rand_core::CryptoRng;
use zeroize::ZeroizeOnDrop;

// Known FIPS 204 signature sizes.
const ML_DSA_44_SIG_LEN: usize = 2420;
const ML_DSA_65_SIG_LEN: usize = 3309;
const ML_DSA_87_SIG_LEN: usize = 4627;

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-44
// ─────────────────────────────────────────────────────────────────────────────

/// Signing (private) key for ML-DSA-44.
pub struct SigningKey44(SigningKey<MlDsa44Params>);
impl ZeroizeOnDrop for SigningKey44 {}

/// Verifying (public) key for ML-DSA-44.
pub struct VerifyingKey44(VerifyingKey<MlDsa44Params>);

/// Signature produced by [`SigningKey44::sign`].
pub struct Signature44(Signature<MlDsa44Params>);

impl fmt::Debug for SigningKey44 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningKey44([seed: 32 bytes, FIPS-204 expanded: {} bytes])",
            MlDsa44::SIGNING_KEY_LEN
        )
    }
}

impl fmt::Debug for VerifyingKey44 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey44({} bytes)", MlDsa44::VERIFYING_KEY_LEN)
    }
}

impl fmt::Debug for Signature44 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature44({} bytes)", MlDsa44::SIGNATURE_LEN)
    }
}

/// ML-DSA-44 parameter set (security category 2, ≈128-bit symmetric).
pub struct MlDsa44;

impl MlDsa44 {
    /// Byte length of the ML-DSA-44 signing key per FIPS 204.
    pub const SIGNING_KEY_LEN: usize = 2560;
    /// Byte length of the ML-DSA-44 verifying key per FIPS 204.
    pub const VERIFYING_KEY_LEN: usize = 1312;
    /// Byte length of an ML-DSA-44 signature per FIPS 204.
    pub const SIGNATURE_LEN: usize = 2420;

    /// Generate a fresh ML-DSA-44 key pair using the provided CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (SigningKey44, VerifyingKey44) {
        let sk = SigningKey::<MlDsa44Params>::generate_from_rng(rng);
        let vk = sk.verifying_key().clone();
        (SigningKey44(sk), VerifyingKey44(vk))
    }
}

impl SigningKey44 {
    /// Sign `msg`, returning a detached signature.
    #[must_use = "result must be checked"]
    pub fn sign(&self, msg: &[u8]) -> Result<Signature44, CryptoError> {
        self.0
            .try_sign(msg)
            .map(Signature44)
            .map_err(|_| CryptoError::Sign)
    }

    /// Serialize the signing key to a 32-byte seed (secret key material).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_seed().as_slice().to_vec()
    }

    /// Deserialize from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Seed = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(SigningKey::<MlDsa44Params>::from_seed(&arr)))
    }
}

impl VerifyingKey44 {
    /// Verify `sig` over `msg`.
    #[must_use = "result must be checked"]
    pub fn verify(&self, msg: &[u8], sig: &Signature44) -> Result<(), CryptoError> {
        self.0.verify(msg, &sig.0).map_err(|_| CryptoError::Sign)
    }

    /// Serialize the verifying key to bytes (1312 bytes for ML-DSA-44).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        KeyExport::to_bytes(&self.0).as_slice().to_vec()
    }

    /// Deserialize a verifying key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded: ml_dsa::EncodedVerifyingKey<MlDsa44Params> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(VerifyingKey::<MlDsa44Params>::decode(&encoded)))
    }
}

impl Signature44 {
    /// Serialize the signature to bytes (2420 bytes for ML-DSA-44).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().as_slice().to_vec()
    }

    /// Deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Signature::<MlDsa44Params>::try_from(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Encoding)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-65
// ─────────────────────────────────────────────────────────────────────────────

/// Signing (private) key for ML-DSA-65.
pub struct SigningKey65(SigningKey<MlDsa65Params>);
impl ZeroizeOnDrop for SigningKey65 {}

/// Verifying (public) key for ML-DSA-65.
pub struct VerifyingKey65(VerifyingKey<MlDsa65Params>);

/// Signature produced by [`SigningKey65::sign`].
pub struct Signature65(Signature<MlDsa65Params>);

impl fmt::Debug for SigningKey65 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningKey65([seed: 32 bytes, FIPS-204 expanded: {} bytes])",
            MlDsa65::SIGNING_KEY_LEN
        )
    }
}

impl fmt::Debug for VerifyingKey65 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey65({} bytes)", MlDsa65::VERIFYING_KEY_LEN)
    }
}

impl fmt::Debug for Signature65 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature65({} bytes)", MlDsa65::SIGNATURE_LEN)
    }
}

/// ML-DSA-65 parameter set (security category 3, ≈192-bit symmetric). Recommended parameter set.
pub struct MlDsa65;

impl MlDsa65 {
    /// Byte length of the ML-DSA-65 signing key per FIPS 204.
    pub const SIGNING_KEY_LEN: usize = 4032;
    /// Byte length of the ML-DSA-65 verifying key per FIPS 204.
    pub const VERIFYING_KEY_LEN: usize = 1952;
    /// Byte length of an ML-DSA-65 signature per FIPS 204.
    pub const SIGNATURE_LEN: usize = 3309;

    /// Generate a fresh ML-DSA-65 key pair using the provided CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (SigningKey65, VerifyingKey65) {
        let sk = SigningKey::<MlDsa65Params>::generate_from_rng(rng);
        let vk = sk.verifying_key().clone();
        (SigningKey65(sk), VerifyingKey65(vk))
    }
}

impl SigningKey65 {
    /// Sign `msg`, returning a detached signature.
    #[must_use = "result must be checked"]
    pub fn sign(&self, msg: &[u8]) -> Result<Signature65, CryptoError> {
        self.0
            .try_sign(msg)
            .map(Signature65)
            .map_err(|_| CryptoError::Sign)
    }

    /// Serialize the signing key to a 32-byte seed (secret key material).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_seed().as_slice().to_vec()
    }

    /// Deserialize from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Seed = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(SigningKey::<MlDsa65Params>::from_seed(&arr)))
    }
}

impl VerifyingKey65 {
    /// Verify `sig` over `msg`.
    #[must_use = "result must be checked"]
    pub fn verify(&self, msg: &[u8], sig: &Signature65) -> Result<(), CryptoError> {
        self.0.verify(msg, &sig.0).map_err(|_| CryptoError::Sign)
    }

    /// Serialize the verifying key to bytes (1952 bytes for ML-DSA-65).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        KeyExport::to_bytes(&self.0).as_slice().to_vec()
    }

    /// Deserialize a verifying key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded: ml_dsa::EncodedVerifyingKey<MlDsa65Params> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(VerifyingKey::<MlDsa65Params>::decode(&encoded)))
    }
}

impl Signature65 {
    /// Serialize the signature to bytes (3309 bytes for ML-DSA-65).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().as_slice().to_vec()
    }

    /// Deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Signature::<MlDsa65Params>::try_from(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Encoding)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-87
// ─────────────────────────────────────────────────────────────────────────────

/// Signing (private) key for ML-DSA-87.
pub struct SigningKey87(SigningKey<MlDsa87Params>);
impl ZeroizeOnDrop for SigningKey87 {}

/// Verifying (public) key for ML-DSA-87.
pub struct VerifyingKey87(VerifyingKey<MlDsa87Params>);

/// Signature produced by [`SigningKey87::sign`].
pub struct Signature87(Signature<MlDsa87Params>);

impl fmt::Debug for SigningKey87 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningKey87([seed: 32 bytes, FIPS-204 expanded: {} bytes])",
            MlDsa87::SIGNING_KEY_LEN
        )
    }
}

impl fmt::Debug for VerifyingKey87 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey87({} bytes)", MlDsa87::VERIFYING_KEY_LEN)
    }
}

impl fmt::Debug for Signature87 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature87({} bytes)", MlDsa87::SIGNATURE_LEN)
    }
}

/// ML-DSA-87 parameter set (security category 5, ≈256-bit symmetric).
pub struct MlDsa87;

impl MlDsa87 {
    /// Byte length of the ML-DSA-87 signing key per FIPS 204.
    pub const SIGNING_KEY_LEN: usize = 4896;
    /// Byte length of the ML-DSA-87 verifying key per FIPS 204.
    pub const VERIFYING_KEY_LEN: usize = 2592;
    /// Byte length of an ML-DSA-87 signature per FIPS 204.
    pub const SIGNATURE_LEN: usize = 4627;

    /// Generate a fresh ML-DSA-87 key pair using the provided CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (SigningKey87, VerifyingKey87) {
        let sk = SigningKey::<MlDsa87Params>::generate_from_rng(rng);
        let vk = sk.verifying_key().clone();
        (SigningKey87(sk), VerifyingKey87(vk))
    }
}

impl SigningKey87 {
    /// Sign `msg`, returning a detached signature.
    #[must_use = "result must be checked"]
    pub fn sign(&self, msg: &[u8]) -> Result<Signature87, CryptoError> {
        self.0
            .try_sign(msg)
            .map(Signature87)
            .map_err(|_| CryptoError::Sign)
    }

    /// Serialize the signing key to a 32-byte seed (secret key material).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_seed().as_slice().to_vec()
    }

    /// Deserialize from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Seed = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(SigningKey::<MlDsa87Params>::from_seed(&arr)))
    }
}

impl VerifyingKey87 {
    /// Verify `sig` over `msg`.
    #[must_use = "result must be checked"]
    pub fn verify(&self, msg: &[u8], sig: &Signature87) -> Result<(), CryptoError> {
        self.0.verify(msg, &sig.0).map_err(|_| CryptoError::Sign)
    }

    /// Serialize the verifying key to bytes (2592 bytes for ML-DSA-87).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        KeyExport::to_bytes(&self.0).as_slice().to_vec()
    }

    /// Deserialize a verifying key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded: ml_dsa::EncodedVerifyingKey<MlDsa87Params> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(VerifyingKey::<MlDsa87Params>::decode(&encoded)))
    }
}

impl Signature87 {
    /// Serialize the signature to bytes (4627 bytes for ML-DSA-87).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().as_slice().to_vec()
    }

    /// Deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Signature::<MlDsa87Params>::try_from(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Encoding)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Trait-dispatch unit structs  (Signer / Verifier from oxicrypto-core)
// ─────────────────────────────────────────────────────────────────────────────

use oxicrypto_core::{Signer, Verifier};

/// ML-DSA-44 trait-dispatch unit struct implementing [`Signer`] and [`Verifier`].
#[derive(Debug, Default, Clone, Copy)]
pub struct MlDsa44Unit;

impl Signer for MlDsa44Unit {
    fn name(&self) -> &'static str {
        "ML-DSA-44"
    }

    fn signature_len(&self) -> usize {
        ML_DSA_44_SIG_LEN
    }

    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < ML_DSA_44_SIG_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let signing_key = SigningKey44::from_bytes(sk)?;
        let sig = signing_key.sign(msg)?;
        let sig_bytes = sig.to_bytes();
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

impl Verifier for MlDsa44Unit {
    fn name(&self) -> &'static str {
        "ML-DSA-44"
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let vk = VerifyingKey44::from_bytes(pk)?;
        let signature = Signature44::from_bytes(sig)?;
        vk.verify(msg, &signature)
    }
}

/// ML-DSA-65 trait-dispatch unit struct implementing [`Signer`] and [`Verifier`].
#[derive(Debug, Default, Clone, Copy)]
pub struct MlDsa65Unit;

impl Signer for MlDsa65Unit {
    fn name(&self) -> &'static str {
        "ML-DSA-65"
    }

    fn signature_len(&self) -> usize {
        ML_DSA_65_SIG_LEN
    }

    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < ML_DSA_65_SIG_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let signing_key = SigningKey65::from_bytes(sk)?;
        let sig = signing_key.sign(msg)?;
        let sig_bytes = sig.to_bytes();
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

impl Verifier for MlDsa65Unit {
    fn name(&self) -> &'static str {
        "ML-DSA-65"
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let vk = VerifyingKey65::from_bytes(pk)?;
        let signature = Signature65::from_bytes(sig)?;
        vk.verify(msg, &signature)
    }
}

/// ML-DSA-87 trait-dispatch unit struct implementing [`Signer`] and [`Verifier`].
#[derive(Debug, Default, Clone, Copy)]
pub struct MlDsa87Unit;

impl Signer for MlDsa87Unit {
    fn name(&self) -> &'static str {
        "ML-DSA-87"
    }

    fn signature_len(&self) -> usize {
        ML_DSA_87_SIG_LEN
    }

    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < ML_DSA_87_SIG_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let signing_key = SigningKey87::from_bytes(sk)?;
        let sig = signing_key.sign(msg)?;
        let sig_bytes = sig.to_bytes();
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

impl Verifier for MlDsa87Unit {
    fn name(&self) -> &'static str {
        "ML-DSA-87"
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let vk = VerifyingKey87::from_bytes(pk)?;
        let signature = Signature87::from_bytes(sig)?;
        vk.verify(msg, &signature)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Context-string signing (FIPS 204 §5.2)
//
//  The `ml-dsa` crate exposes `ExpandedSigningKey::sign_randomized(msg, ctx, rng)`
//  and `VerifyingKey::verify_with_context(msg, ctx, sig)`.  These wrappers expose
//  the same functionality through our byte-slice API for ergonomic use without
//  exposing the upstream crate's types.
//
//  Context string rules (FIPS 204 §5.2):
//  - Context must be ≤ 255 bytes; longer contexts are rejected with `CryptoError::InvalidKey`.
//  - The empty context `b""` is valid and distinct from non-empty contexts.
// ─────────────────────────────────────────────────────────────────────────────

/// Sign `msg` with a domain-separation context string using ML-DSA-44 (FIPS 204 §5.2).
///
/// # Arguments
/// * `sk` — 32-byte signing-key seed.
/// * `msg` — message to sign.
/// * `ctx` — context string for domain separation; must be ≤ 255 bytes.
/// * `out` — output buffer; must be ≥ [`MlDsa44::SIGNATURE_LEN`] bytes.
/// * `rng` — CSPRNG for hedged (randomised) signing per FIPS 204.
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `ctx.len() > 255`, [`CryptoError::BufferTooSmall`]
/// if `out` is too short, or [`CryptoError::Encoding`] on bad key bytes.
pub fn mldsa44_sign_ctx<R: CryptoRng>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    out: &mut [u8],
    rng: &mut R,
) -> Result<usize, CryptoError> {
    if ctx.len() > 255 {
        return Err(CryptoError::InvalidKey);
    }
    if out.len() < ML_DSA_44_SIG_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let sk_inner = SigningKey44::from_bytes(sk)?;
    let sig = sk_inner
        .0
        .expanded_key()
        .sign_randomized(msg, ctx, rng)
        .map_err(|_| CryptoError::Sign)?;
    let sig_bytes = sig.encode();
    out[..ML_DSA_44_SIG_LEN].copy_from_slice(&sig_bytes);
    Ok(ML_DSA_44_SIG_LEN)
}

/// Verify a context-string ML-DSA-44 signature (FIPS 204 §5.2).
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `ctx.len() > 255`, [`CryptoError::Encoding`]
/// on bad key/signature bytes, or [`CryptoError::Sign`] on verification failure.
pub fn mldsa44_verify_ctx(
    vk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<(), CryptoError> {
    if ctx.len() > 255 {
        return Err(CryptoError::InvalidKey);
    }
    let vk_inner = VerifyingKey44::from_bytes(vk)?;
    let signature = Signature44::from_bytes(sig)?;
    if vk_inner.0.verify_with_context(msg, ctx, &signature.0) {
        Ok(())
    } else {
        Err(CryptoError::Sign)
    }
}

/// Sign `msg` with a domain-separation context string using ML-DSA-65 (FIPS 204 §5.2).
///
/// # Arguments
/// * `sk` — 32-byte signing-key seed.
/// * `msg` — message to sign.
/// * `ctx` — context string for domain separation; must be ≤ 255 bytes.
/// * `out` — output buffer; must be ≥ [`MlDsa65::SIGNATURE_LEN`] bytes.
/// * `rng` — CSPRNG for hedged (randomised) signing per FIPS 204.
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `ctx.len() > 255`, [`CryptoError::BufferTooSmall`]
/// if `out` is too short, or [`CryptoError::Encoding`] on bad key bytes.
pub fn mldsa65_sign_ctx<R: CryptoRng>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    out: &mut [u8],
    rng: &mut R,
) -> Result<usize, CryptoError> {
    if ctx.len() > 255 {
        return Err(CryptoError::InvalidKey);
    }
    if out.len() < ML_DSA_65_SIG_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let sk_inner = SigningKey65::from_bytes(sk)?;
    let sig = sk_inner
        .0
        .expanded_key()
        .sign_randomized(msg, ctx, rng)
        .map_err(|_| CryptoError::Sign)?;
    let sig_bytes = sig.encode();
    out[..ML_DSA_65_SIG_LEN].copy_from_slice(&sig_bytes);
    Ok(ML_DSA_65_SIG_LEN)
}

/// Verify a context-string ML-DSA-65 signature (FIPS 204 §5.2).
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `ctx.len() > 255`, [`CryptoError::Encoding`]
/// on bad key/signature bytes, or [`CryptoError::Sign`] on verification failure.
pub fn mldsa65_verify_ctx(
    vk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<(), CryptoError> {
    if ctx.len() > 255 {
        return Err(CryptoError::InvalidKey);
    }
    let vk_inner = VerifyingKey65::from_bytes(vk)?;
    let signature = Signature65::from_bytes(sig)?;
    if vk_inner.0.verify_with_context(msg, ctx, &signature.0) {
        Ok(())
    } else {
        Err(CryptoError::Sign)
    }
}

/// Sign `msg` with a domain-separation context string using ML-DSA-87 (FIPS 204 §5.2).
///
/// # Arguments
/// * `sk` — 32-byte signing-key seed.
/// * `msg` — message to sign.
/// * `ctx` — context string for domain separation; must be ≤ 255 bytes.
/// * `out` — output buffer; must be ≥ [`MlDsa87::SIGNATURE_LEN`] bytes.
/// * `rng` — CSPRNG for hedged (randomised) signing per FIPS 204.
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `ctx.len() > 255`, [`CryptoError::BufferTooSmall`]
/// if `out` is too short, or [`CryptoError::Encoding`] on bad key bytes.
pub fn mldsa87_sign_ctx<R: CryptoRng>(
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    out: &mut [u8],
    rng: &mut R,
) -> Result<usize, CryptoError> {
    if ctx.len() > 255 {
        return Err(CryptoError::InvalidKey);
    }
    if out.len() < ML_DSA_87_SIG_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let sk_inner = SigningKey87::from_bytes(sk)?;
    let sig = sk_inner
        .0
        .expanded_key()
        .sign_randomized(msg, ctx, rng)
        .map_err(|_| CryptoError::Sign)?;
    let sig_bytes = sig.encode();
    out[..ML_DSA_87_SIG_LEN].copy_from_slice(&sig_bytes);
    Ok(ML_DSA_87_SIG_LEN)
}

/// Verify a context-string ML-DSA-87 signature (FIPS 204 §5.2).
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `ctx.len() > 255`, [`CryptoError::Encoding`]
/// on bad key/signature bytes, or [`CryptoError::Sign`] on verification failure.
pub fn mldsa87_verify_ctx(
    vk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<(), CryptoError> {
    if ctx.len() > 255 {
        return Err(CryptoError::InvalidKey);
    }
    let vk_inner = VerifyingKey87::from_bytes(vk)?;
    let signature = Signature87::from_bytes(sig)?;
    if vk_inner.0.verify_with_context(msg, ctx, &signature.0) {
        Ok(())
    } else {
        Err(CryptoError::Sign)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const TEST_MSG: &[u8] = b"oxicrypto-pq ML-DSA test message";

    #[test]
    fn mldsa44_sign_verify_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);
        let (sk, vk) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        vk.verify(TEST_MSG, &sig).expect("verify failed");
    }

    #[test]
    fn mldsa44_wrong_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);
        let (sk, vk) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let mut altered = TEST_MSG.to_vec();
        altered[0] ^= 0x01;
        assert!(
            vk.verify(&altered, &sig).is_err(),
            "verify should fail on altered message"
        );
    }

    #[test]
    fn mldsa65_sign_verify_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);
        let (sk, vk) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        vk.verify(TEST_MSG, &sig).expect("verify failed");
    }

    #[test]
    fn mldsa65_wrong_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);
        let (sk, vk) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let mut altered = TEST_MSG.to_vec();
        altered[0] ^= 0x01;
        assert!(
            vk.verify(&altered, &sig).is_err(),
            "verify should fail on altered message"
        );
    }

    #[test]
    fn mldsa87_sign_verify_round_trip() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);
                let (sk, vk) = MlDsa87::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                vk.verify(TEST_MSG, &sig).expect("verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn mldsa87_wrong_message_fails() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);
                let (sk, vk) = MlDsa87::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                let mut altered = TEST_MSG.to_vec();
                altered[0] ^= 0x01;
                assert!(
                    vk.verify(&altered, &sig).is_err(),
                    "verify should fail on altered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn mldsa44_signing_key_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0xBBu8; 32]);
        let (sk_orig, vk) = MlDsa44::generate(&mut rng);
        let sk_bytes = sk_orig.to_bytes();
        assert_eq!(
            sk_bytes.len(),
            32,
            "ML-DSA-44 signing seed must be 32 bytes"
        );
        let sk2 = SigningKey44::from_bytes(&sk_bytes).expect("from_bytes failed");
        let sig = sk2.sign(TEST_MSG).expect("sign failed");
        vk.verify(TEST_MSG, &sig).expect("verify failed");
    }

    #[test]
    fn mldsa65_signing_key_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0xCCu8; 32]);
        let (sk_orig, vk) = MlDsa65::generate(&mut rng);
        let sk_bytes = sk_orig.to_bytes();
        assert_eq!(
            sk_bytes.len(),
            32,
            "ML-DSA-65 signing seed must be 32 bytes"
        );
        let sk2 = SigningKey65::from_bytes(&sk_bytes).expect("from_bytes failed");
        let sig = sk2.sign(TEST_MSG).expect("sign failed");
        vk.verify(TEST_MSG, &sig).expect("verify failed");
    }

    #[test]
    fn mldsa87_signing_key_roundtrip() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xDDu8; 32]);
                let (sk_orig, vk) = MlDsa87::generate(&mut rng);
                let sk_bytes = sk_orig.to_bytes();
                assert_eq!(
                    sk_bytes.len(),
                    32,
                    "ML-DSA-87 signing seed must be 32 bytes"
                );
                let sk2 = SigningKey87::from_bytes(&sk_bytes).expect("from_bytes failed");
                let sig = sk2.sign(TEST_MSG).expect("sign failed");
                vk.verify(TEST_MSG, &sig).expect("verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn mldsa44_verifying_key_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0xEEu8; 32]);
        let (sk, vk_orig) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let vk_bytes = vk_orig.to_bytes();
        let vk2 = VerifyingKey44::from_bytes(&vk_bytes).expect("from_bytes failed");
        vk2.verify(TEST_MSG, &sig)
            .expect("verify via deserialized vk failed");
    }

    #[test]
    fn mldsa65_verifying_key_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0xFFu8; 32]);
        let (sk, vk_orig) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let vk_bytes = vk_orig.to_bytes();
        let vk2 = VerifyingKey65::from_bytes(&vk_bytes).expect("from_bytes failed");
        vk2.verify(TEST_MSG, &sig)
            .expect("verify via deserialized vk failed");
    }

    #[test]
    fn mldsa87_verifying_key_roundtrip() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x11u8; 32]);
                let (sk, vk_orig) = MlDsa87::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                let vk_bytes = vk_orig.to_bytes();
                let vk2 = VerifyingKey87::from_bytes(&vk_bytes).expect("from_bytes failed");
                vk2.verify(TEST_MSG, &sig)
                    .expect("verify via deserialized vk failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn mldsa44_signature_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x22u8; 32]);
        let (sk, vk) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), ML_DSA_44_SIG_LEN);
        let sig2 = Signature44::from_bytes(&sig_bytes).expect("from_bytes failed");
        vk.verify(TEST_MSG, &sig2)
            .expect("verify deserialized signature failed");
    }

    #[test]
    fn mldsa65_signature_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
        let (sk, vk) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), ML_DSA_65_SIG_LEN);
        let sig2 = Signature65::from_bytes(&sig_bytes).expect("from_bytes failed");
        vk.verify(TEST_MSG, &sig2)
            .expect("verify deserialized signature failed");
    }

    #[test]
    fn mldsa87_signature_roundtrip() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x44u8; 32]);
                let (sk, vk) = MlDsa87::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                let sig_bytes = sig.to_bytes();
                assert_eq!(sig_bytes.len(), ML_DSA_87_SIG_LEN);
                let sig2 = Signature87::from_bytes(&sig_bytes).expect("from_bytes failed");
                vk.verify(TEST_MSG, &sig2)
                    .expect("verify deserialized signature failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn signing_key_from_bytes_wrong_length_fails() {
        assert!(SigningKey44::from_bytes(&[0u8; 16]).is_err());
        assert!(SigningKey65::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn verifying_key_from_bytes_wrong_length_fails() {
        assert!(VerifyingKey44::from_bytes(&[0u8; 16]).is_err());
    }

    #[test]
    fn signature_from_bytes_wrong_length_fails() {
        assert!(Signature44::from_bytes(&[0u8; 16]).is_err());
    }

    // ── Signer / Verifier trait tests ─────────────────────────────────────────

    #[test]
    fn mldsa44_signer_verifier_trait() {
        let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
        let (sk_typed, vk_typed) = MlDsa44::generate(&mut rng);
        let sk_bytes = sk_typed.to_bytes();
        let vk_bytes = vk_typed.to_bytes();

        let signer = MlDsa44Unit;
        let verifier = MlDsa44Unit;

        let mut sig_buf = vec![0u8; ML_DSA_44_SIG_LEN];
        let written = signer
            .sign(&sk_bytes, TEST_MSG, &mut sig_buf)
            .expect("trait sign failed");
        assert_eq!(written, ML_DSA_44_SIG_LEN);
        verifier
            .verify(&vk_bytes, TEST_MSG, &sig_buf)
            .expect("trait verify failed");
    }

    #[test]
    fn mldsa65_signer_verifier_trait() {
        let mut rng = ChaCha20Rng::from_seed([0x66u8; 32]);
        let (sk_typed, vk_typed) = MlDsa65::generate(&mut rng);
        let sk_bytes = sk_typed.to_bytes();
        let vk_bytes = vk_typed.to_bytes();

        let signer = MlDsa65Unit;
        let verifier = MlDsa65Unit;

        let mut sig_buf = vec![0u8; ML_DSA_65_SIG_LEN];
        let written = signer
            .sign(&sk_bytes, TEST_MSG, &mut sig_buf)
            .expect("trait sign failed");
        assert_eq!(written, ML_DSA_65_SIG_LEN);
        verifier
            .verify(&vk_bytes, TEST_MSG, &sig_buf)
            .expect("trait verify failed");
    }

    #[test]
    fn mldsa87_signer_verifier_trait() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x77u8; 32]);
                let (sk_typed, vk_typed) = MlDsa87::generate(&mut rng);
                let sk_bytes = sk_typed.to_bytes();
                let vk_bytes = vk_typed.to_bytes();

                let signer = MlDsa87Unit;
                let verifier = MlDsa87Unit;

                let mut sig_buf = vec![0u8; ML_DSA_87_SIG_LEN];
                let written = signer
                    .sign(&sk_bytes, TEST_MSG, &mut sig_buf)
                    .expect("trait sign failed");
                assert_eq!(written, ML_DSA_87_SIG_LEN);
                verifier
                    .verify(&vk_bytes, TEST_MSG, &sig_buf)
                    .expect("trait verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn mldsa44_signer_trait_buffer_too_small() {
        let mut rng = ChaCha20Rng::from_seed([0x88u8; 32]);
        let (sk_typed, _) = MlDsa44::generate(&mut rng);
        let sk_bytes = sk_typed.to_bytes();

        let signer = MlDsa44Unit;
        let mut tiny = vec![0u8; 10];
        let result = signer.sign(&sk_bytes, TEST_MSG, &mut tiny);
        assert_eq!(result, Err(CryptoError::BufferTooSmall));
    }

    #[test]
    fn mldsa44_verifier_trait_wrong_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0x99u8; 32]);
        let (sk_typed, vk_typed) = MlDsa44::generate(&mut rng);
        let sk_bytes = sk_typed.to_bytes();
        let vk_bytes = vk_typed.to_bytes();

        let signer = MlDsa44Unit;
        let verifier = MlDsa44Unit;

        let mut sig_buf = vec![0u8; ML_DSA_44_SIG_LEN];
        signer
            .sign(&sk_bytes, TEST_MSG, &mut sig_buf)
            .expect("sign failed");

        let mut altered = TEST_MSG.to_vec();
        altered[0] ^= 0x01;
        assert!(
            verifier.verify(&vk_bytes, &altered, &sig_buf).is_err(),
            "verify should fail on altered message"
        );
    }

    // ── SA-3: size constants ──────────────────────────────────────────────────

    #[test]
    fn test_mldsa_key_size_constants() {
        assert_eq!(MlDsa44::SIGNING_KEY_LEN, 2560);
        assert_eq!(MlDsa44::VERIFYING_KEY_LEN, 1312);
        assert_eq!(MlDsa44::SIGNATURE_LEN, 2420);

        assert_eq!(MlDsa65::SIGNING_KEY_LEN, 4032);
        assert_eq!(MlDsa65::VERIFYING_KEY_LEN, 1952);
        assert_eq!(MlDsa65::SIGNATURE_LEN, 3309);

        assert_eq!(MlDsa87::SIGNING_KEY_LEN, 4896);
        assert_eq!(MlDsa87::VERIFYING_KEY_LEN, 2592);
        assert_eq!(MlDsa87::SIGNATURE_LEN, 4627);
    }

    #[test]
    fn test_mldsa44_key_byte_lengths_match_constants() {
        let mut rng = ChaCha20Rng::from_seed([0xA1u8; 32]);
        let (sk, vk) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        assert_eq!(vk.to_bytes().len(), MlDsa44::VERIFYING_KEY_LEN);
        assert_eq!(sig.to_bytes().len(), MlDsa44::SIGNATURE_LEN);
    }

    #[test]
    fn test_mldsa65_key_byte_lengths_match_constants() {
        let mut rng = ChaCha20Rng::from_seed([0xA2u8; 32]);
        let (sk, vk) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        assert_eq!(vk.to_bytes().len(), MlDsa65::VERIFYING_KEY_LEN);
        assert_eq!(sig.to_bytes().len(), MlDsa65::SIGNATURE_LEN);
    }

    // ── SA-3: Debug impls ─────────────────────────────────────────────────────

    #[test]
    fn test_mldsa44_debug_does_not_leak() {
        let mut rng = ChaCha20Rng::from_seed([0xB1u8; 32]);
        let (sk, vk) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");

        let sk_dbg = format!("{sk:?}");
        let vk_dbg = format!("{vk:?}");
        let sig_dbg = format!("{sig:?}");

        assert!(
            sk_dbg.contains("SigningKey44"),
            "SigningKey44 debug missing type name"
        );
        assert!(
            vk_dbg.contains("VerifyingKey44"),
            "VerifyingKey44 debug missing type name"
        );
        assert!(
            vk_dbg.contains("1312"),
            "VerifyingKey44 debug missing byte count"
        );
        assert!(
            sig_dbg.contains("Signature44"),
            "Signature44 debug missing type name"
        );
        assert!(
            sig_dbg.contains("2420"),
            "Signature44 debug missing byte count"
        );

        // No raw key material should appear in the debug output.
        let hex_run: bool = sk_dbg
            .split_whitespace()
            .any(|tok| tok.len() > 6 && tok.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hex_run, "SigningKey44 debug must not dump raw hex bytes");
    }

    #[test]
    fn test_mldsa65_debug_type_names() {
        let mut rng = ChaCha20Rng::from_seed([0xB2u8; 32]);
        let (sk, vk) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");

        assert!(format!("{sk:?}").contains("SigningKey65"));
        assert!(format!("{vk:?}").contains("VerifyingKey65"));
        assert!(format!("{sig:?}").contains("Signature65"));
    }
}
