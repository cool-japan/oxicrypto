//! ML-KEM (FIPS 203) post-quantum key-encapsulation mechanism.
//!
//! Provides three parameter sets:
//!
//! | Type | Security | Ciphertext | Public key |
//! |------|----------|-----------|------------|
//! | [`MlKem512`]  | Category 1 (≈128-bit) | 768 B  | 800 B  |
//! | [`MlKem768`]  | Category 3 (≈192-bit) | 1088 B | 1184 B |
//! | [`MlKem1024`] | Category 5 (≈256-bit) | 1568 B | 1568 B |
//!
//! # Usage
//!
//! ```rust
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//! use oxicrypto_pq::mlkem::MlKem768;
//!
//! let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
//! let (dk, ek) = MlKem768::generate(&mut rng);
//! let (ct, ss_enc) = ek.encapsulate(&mut rng).unwrap();
//! let ss_dec = dk.decapsulate(&ct).unwrap();
//! assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
//! ```

use core::fmt;
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Generate, KeyExport,
    MlKem1024 as MlKem1024Params, MlKem512 as MlKem512Params, MlKem768 as MlKem768Params, Seed,
};
use oxicrypto_core::Kem;
// `Seed` for deterministic helper is only used in hazmat path; `ml_kem::Seed` is re-imported
// below inside the cfg-gated helper so we also need an unconditional one for DecapKey
// serialization.  The import above covers both.
//
// `B32` (for encapsulate_deterministic) also only needed under the cfg gate.
#[cfg(any(test, feature = "hazmat-test-vectors"))]
use ml_kem::B32;
use oxicrypto_core::{ConstantTimeEq, CryptoError};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─────────────────────────────────────────────────────────────────────────────
//  Shared-key wrapper — stored as raw [u8; 32] so we can Zeroize it safely.
// ─────────────────────────────────────────────────────────────────────────────

/// A 32-byte ML-KEM shared secret, automatically zeroed when dropped.
///
/// Use [`SharedSecret::as_slice`] to access the raw bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Construct from the upstream `SharedKey` (a `[u8; 32]` newtype).
    #[inline]
    pub(crate) fn from_ml_kem(sk: ml_kem::SharedKey) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(sk.as_ref());
        Self(bytes)
    }

    /// Returns a reference to the 32 raw bytes of this shared secret.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a reference to the raw bytes (alias for [`as_slice`](Self::as_slice)).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SharedSecret(***)")
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref().ct_eq(other.0.as_ref()).into()
    }
}

impl Eq for SharedSecret {}

/// Backwards-compatibility alias for [`SharedSecret`].
///
/// New code should use `SharedSecret` directly.
#[deprecated(since = "0.0.0", note = "use `SharedSecret` instead")]
pub type SharedKeyPq = SharedSecret;

// ─────────────────────────────────────────────────────────────────────────────
//  helper: seed_from_bytes  (hazmat / test only)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "hazmat-test-vectors"))]
fn seed_from_bytes(bytes: &[u8; 64]) -> Seed {
    (*bytes).into()
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-512
// ─────────────────────────────────────────────────────────────────────────────

/// Encapsulation (public) key for ML-KEM-512.
pub struct EncapKey512(EncapsulationKey<MlKem512Params>);

/// Decapsulation (private) key for ML-KEM-512.
///
/// Automatically zeroes its seed material on drop (when `zeroize` feature is
/// enabled in `ml-kem`).
pub struct DecapKey512(DecapsulationKey<MlKem512Params>);

// `DecapsulationKey` already implements `ZeroizeOnDrop` (when ml-kem/zeroize feature is on).
// We propagate that guarantee via our wrapper.
impl ZeroizeOnDrop for DecapKey512 {}

/// Ciphertext produced by [`EncapKey512::encapsulate`].
pub struct Ciphertext512(Ciphertext<MlKem512Params>);

impl fmt::Debug for EncapKey512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncapKey512({} bytes)", MlKem512::ENCAP_KEY_LEN)
    }
}

impl fmt::Debug for DecapKey512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecapKey512([seed: 64 bytes, FIPS-203 expanded: {} bytes])",
            MlKem512::DECAP_KEY_LEN
        )
    }
}

impl fmt::Debug for Ciphertext512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext512({} bytes)", MlKem512::CIPHERTEXT_LEN)
    }
}

impl Ciphertext512 {
    /// Serialize the ciphertext to bytes (768 bytes for ML-KEM-512).
    pub fn to_bytes(&self) -> Vec<u8> {
        let slice: &[u8] = &self.0;
        slice.to_vec()
    }

    /// Deserialize a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Ciphertext<MlKem512Params> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(arr))
    }
}

/// ML-KEM-512 parameter set (security category 1, ≈128-bit equivalent).
pub struct MlKem512;

impl MlKem512 {
    /// Byte length of the encapsulation (public) key per FIPS 203.
    pub const ENCAP_KEY_LEN: usize = 800;
    /// Byte length of the decapsulation (private) key in FIPS 203 expanded form.
    ///
    /// Note: our `DecapKey512::from_bytes` / `to_bytes` uses a 64-byte seed for
    /// compact serialization. This constant reflects the full FIPS 203 wire size.
    pub const DECAP_KEY_LEN: usize = 1632;
    /// Byte length of the ML-KEM-512 ciphertext per FIPS 203.
    pub const CIPHERTEXT_LEN: usize = 768;
    /// Byte length of the shared secret produced by encapsulation/decapsulation.
    pub const SHARED_SECRET_LEN: usize = 32;

    /// Generate a fresh ML-KEM-512 key pair using the provided CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (DecapKey512, EncapKey512) {
        let dk = DecapsulationKey::<MlKem512Params>::generate_from_rng(rng);
        let ek = dk.encapsulation_key().clone();
        (DecapKey512(dk), EncapKey512(ek))
    }

    /// Generate a ML-KEM-512 key pair deterministically from a 64-byte seed.
    ///
    /// **Warning**: This is intended for testing / KAT only.  Reusing seeds is
    /// catastrophically insecure.
    #[cfg(any(test, feature = "hazmat-test-vectors"))]
    pub fn generate_deterministic(seed: &[u8; 64]) -> (DecapKey512, EncapKey512) {
        let s = seed_from_bytes(seed);
        let dk = DecapsulationKey::<MlKem512Params>::from_seed(s);
        let ek = dk.encapsulation_key().clone();
        (DecapKey512(dk), EncapKey512(ek))
    }
}

impl EncapKey512 {
    /// Encapsulate a fresh shared key, returning `(ciphertext, shared_key)`.
    #[must_use = "result must be checked"]
    pub fn encapsulate<R: CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext512, SharedSecret), CryptoError> {
        let (ct, ss) = self.0.encapsulate_with_rng(rng);
        Ok((Ciphertext512(ct), SharedSecret::from_ml_kem(ss)))
    }

    /// Encapsulate deterministically using the 32-byte randomness `m`.
    ///
    /// **Warning**: Testing / KAT only.
    #[cfg(any(test, feature = "hazmat-test-vectors"))]
    #[must_use = "result must be checked"]
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
    ) -> Result<(Ciphertext512, SharedSecret), CryptoError> {
        let b32: B32 = (*m).into();
        let (ct, ss) = self.0.encapsulate_deterministic(&b32);
        Ok((Ciphertext512(ct), SharedSecret::from_ml_kem(ss)))
    }

    /// Serialize the encapsulation key to bytes (800 bytes for ML-KEM-512).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let arr = self.0.to_bytes();
        arr[..].to_vec()
    }

    /// Deserialize an encapsulation key from bytes.
    ///
    /// Returns [`CryptoError::Encoding`] if the byte length is wrong, or
    /// [`CryptoError::InvalidKey`] if the key fails FIPS 203 §7.2 validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: ml_kem::Key<EncapsulationKey<MlKem512Params>> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        EncapsulationKey::<MlKem512Params>::new(&arr)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl DecapKey512 {
    /// Decapsulate `ct`, recovering the shared key.
    #[must_use = "result must be checked"]
    pub fn decapsulate(&self, ct: &Ciphertext512) -> Result<SharedSecret, CryptoError> {
        let ss = self.0.decapsulate(&ct.0);
        Ok(SharedSecret::from_ml_kem(ss))
    }

    /// Serialize the decapsulation key to a 64-byte seed.
    ///
    /// Returns [`CryptoError::Encoding`] if the key was not initialized from a
    /// seed (this cannot happen when using the public API).
    #[must_use = "result must be checked"]
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.0
            .to_seed()
            .map(|s| s[..].to_vec())
            .ok_or(CryptoError::Encoding)
    }

    /// Deserialize a decapsulation key from a 64-byte seed.
    ///
    /// Returns [`CryptoError::Encoding`] if `bytes` is not exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Seed = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(DecapsulationKey::<MlKem512Params>::from_seed(arr)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-768
// ─────────────────────────────────────────────────────────────────────────────

/// Encapsulation (public) key for ML-KEM-768.
#[derive(Clone)]
pub struct EncapKey768(EncapsulationKey<MlKem768Params>);

/// Decapsulation (private) key for ML-KEM-768.
///
/// Automatically zeroes its seed material on drop.
pub struct DecapKey768(DecapsulationKey<MlKem768Params>);

impl ZeroizeOnDrop for DecapKey768 {}

/// Ciphertext produced by [`EncapKey768::encapsulate`].
#[derive(Clone)]
pub struct Ciphertext768(Ciphertext<MlKem768Params>);

impl fmt::Debug for EncapKey768 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncapKey768({} bytes)", MlKem768::ENCAP_KEY_LEN)
    }
}

impl fmt::Debug for DecapKey768 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecapKey768([seed: 64 bytes, FIPS-203 expanded: {} bytes])",
            MlKem768::DECAP_KEY_LEN
        )
    }
}

impl fmt::Debug for Ciphertext768 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext768({} bytes)", MlKem768::CIPHERTEXT_LEN)
    }
}

impl Ciphertext768 {
    /// Serialize the ciphertext to bytes (1088 bytes for ML-KEM-768).
    pub fn to_bytes(&self) -> Vec<u8> {
        let slice: &[u8] = &self.0;
        slice.to_vec()
    }

    /// Deserialize a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Ciphertext<MlKem768Params> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(arr))
    }
}

/// ML-KEM-768 parameter set (security category 3, ≈192-bit equivalent).
pub struct MlKem768;

impl MlKem768 {
    /// Byte length of the encapsulation (public) key per FIPS 203.
    pub const ENCAP_KEY_LEN: usize = 1184;
    /// Byte length of the decapsulation (private) key in FIPS 203 expanded form.
    ///
    /// Note: our `DecapKey768::from_bytes` / `to_bytes` uses a 64-byte seed for
    /// compact serialization. This constant reflects the full FIPS 203 wire size.
    pub const DECAP_KEY_LEN: usize = 2400;
    /// Byte length of the ML-KEM-768 ciphertext per FIPS 203.
    pub const CIPHERTEXT_LEN: usize = 1088;
    /// Byte length of the shared secret produced by encapsulation/decapsulation.
    pub const SHARED_SECRET_LEN: usize = 32;

    /// Generate a fresh ML-KEM-768 key pair using the provided CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (DecapKey768, EncapKey768) {
        let dk = DecapsulationKey::<MlKem768Params>::generate_from_rng(rng);
        let ek = dk.encapsulation_key().clone();
        (DecapKey768(dk), EncapKey768(ek))
    }

    /// Generate a ML-KEM-768 key pair deterministically from a 64-byte seed.
    ///
    /// **Warning**: This is intended for testing / KAT only.
    #[cfg(any(test, feature = "hazmat-test-vectors"))]
    pub fn generate_deterministic(seed: &[u8; 64]) -> (DecapKey768, EncapKey768) {
        let s = seed_from_bytes(seed);
        let dk = DecapsulationKey::<MlKem768Params>::from_seed(s);
        let ek = dk.encapsulation_key().clone();
        (DecapKey768(dk), EncapKey768(ek))
    }
}

impl EncapKey768 {
    /// Encapsulate a fresh shared key, returning `(ciphertext, shared_key)`.
    #[must_use = "result must be checked"]
    pub fn encapsulate<R: CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext768, SharedSecret), CryptoError> {
        let (ct, ss) = self.0.encapsulate_with_rng(rng);
        Ok((Ciphertext768(ct), SharedSecret::from_ml_kem(ss)))
    }

    /// Encapsulate deterministically using the 32-byte randomness `m`.
    ///
    /// **Warning**: Testing / KAT only.
    #[cfg(any(test, feature = "hazmat-test-vectors"))]
    #[must_use = "result must be checked"]
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
    ) -> Result<(Ciphertext768, SharedSecret), CryptoError> {
        let b32: B32 = (*m).into();
        let (ct, ss) = self.0.encapsulate_deterministic(&b32);
        Ok((Ciphertext768(ct), SharedSecret::from_ml_kem(ss)))
    }

    /// Serialize the encapsulation key to bytes (1184 bytes for ML-KEM-768).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let arr = self.0.to_bytes();
        arr[..].to_vec()
    }

    /// Deserialize an encapsulation key from bytes.
    ///
    /// Returns [`CryptoError::Encoding`] if the byte length is wrong, or
    /// [`CryptoError::InvalidKey`] if the key fails FIPS 203 §7.2 validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: ml_kem::Key<EncapsulationKey<MlKem768Params>> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        EncapsulationKey::<MlKem768Params>::new(&arr)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl DecapKey768 {
    /// Decapsulate `ct`, recovering the shared key.
    #[must_use = "result must be checked"]
    pub fn decapsulate(&self, ct: &Ciphertext768) -> Result<SharedSecret, CryptoError> {
        let ss = self.0.decapsulate(&ct.0);
        Ok(SharedSecret::from_ml_kem(ss))
    }

    /// Serialize the decapsulation key to a 64-byte seed.
    #[must_use = "result must be checked"]
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.0
            .to_seed()
            .map(|s| s[..].to_vec())
            .ok_or(CryptoError::Encoding)
    }

    /// Deserialize a decapsulation key from a 64-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Seed = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(DecapsulationKey::<MlKem768Params>::from_seed(arr)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-1024
// ─────────────────────────────────────────────────────────────────────────────

/// Encapsulation (public) key for ML-KEM-1024.
#[derive(Clone)]
pub struct EncapKey1024(EncapsulationKey<MlKem1024Params>);

/// Decapsulation (private) key for ML-KEM-1024.
///
/// Automatically zeroes its seed material on drop.
pub struct DecapKey1024(DecapsulationKey<MlKem1024Params>);

impl ZeroizeOnDrop for DecapKey1024 {}

/// Ciphertext produced by [`EncapKey1024::encapsulate`].
#[derive(Clone)]
pub struct Ciphertext1024(Ciphertext<MlKem1024Params>);

impl fmt::Debug for EncapKey1024 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncapKey1024({} bytes)", MlKem1024::ENCAP_KEY_LEN)
    }
}

impl fmt::Debug for DecapKey1024 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecapKey1024([seed: 64 bytes, FIPS-203 expanded: {} bytes])",
            MlKem1024::DECAP_KEY_LEN
        )
    }
}

impl fmt::Debug for Ciphertext1024 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext1024({} bytes)", MlKem1024::CIPHERTEXT_LEN)
    }
}

impl Ciphertext1024 {
    /// Serialize the ciphertext to bytes (1568 bytes for ML-KEM-1024).
    pub fn to_bytes(&self) -> Vec<u8> {
        let slice: &[u8] = &self.0;
        slice.to_vec()
    }

    /// Deserialize a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Ciphertext<MlKem1024Params> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(arr))
    }
}

/// ML-KEM-1024 parameter set (security category 5, ≈256-bit equivalent).
pub struct MlKem1024;

impl MlKem1024 {
    /// Byte length of the encapsulation (public) key per FIPS 203.
    pub const ENCAP_KEY_LEN: usize = 1568;
    /// Byte length of the decapsulation (private) key in FIPS 203 expanded form.
    ///
    /// Note: our `DecapKey1024::from_bytes` / `to_bytes` uses a 64-byte seed for
    /// compact serialization. This constant reflects the full FIPS 203 wire size.
    pub const DECAP_KEY_LEN: usize = 3168;
    /// Byte length of the ML-KEM-1024 ciphertext per FIPS 203.
    pub const CIPHERTEXT_LEN: usize = 1568;
    /// Byte length of the shared secret produced by encapsulation/decapsulation.
    pub const SHARED_SECRET_LEN: usize = 32;

    /// Generate a fresh ML-KEM-1024 key pair using the provided CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (DecapKey1024, EncapKey1024) {
        let dk = DecapsulationKey::<MlKem1024Params>::generate_from_rng(rng);
        let ek = dk.encapsulation_key().clone();
        (DecapKey1024(dk), EncapKey1024(ek))
    }

    /// Generate a ML-KEM-1024 key pair deterministically from a 64-byte seed.
    ///
    /// **Warning**: This is intended for testing / KAT only.
    #[cfg(any(test, feature = "hazmat-test-vectors"))]
    pub fn generate_deterministic(seed: &[u8; 64]) -> (DecapKey1024, EncapKey1024) {
        let s = seed_from_bytes(seed);
        let dk = DecapsulationKey::<MlKem1024Params>::from_seed(s);
        let ek = dk.encapsulation_key().clone();
        (DecapKey1024(dk), EncapKey1024(ek))
    }
}

impl EncapKey1024 {
    /// Encapsulate a fresh shared key, returning `(ciphertext, shared_key)`.
    #[must_use = "result must be checked"]
    pub fn encapsulate<R: CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext1024, SharedSecret), CryptoError> {
        let (ct, ss) = self.0.encapsulate_with_rng(rng);
        Ok((Ciphertext1024(ct), SharedSecret::from_ml_kem(ss)))
    }

    /// Encapsulate deterministically using the 32-byte randomness `m`.
    ///
    /// **Warning**: Testing / KAT only.
    #[cfg(any(test, feature = "hazmat-test-vectors"))]
    #[must_use = "result must be checked"]
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
    ) -> Result<(Ciphertext1024, SharedSecret), CryptoError> {
        let b32: B32 = (*m).into();
        let (ct, ss) = self.0.encapsulate_deterministic(&b32);
        Ok((Ciphertext1024(ct), SharedSecret::from_ml_kem(ss)))
    }

    /// Serialize the encapsulation key to bytes (1568 bytes for ML-KEM-1024).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let arr = self.0.to_bytes();
        arr[..].to_vec()
    }

    /// Deserialize an encapsulation key from bytes.
    ///
    /// Returns [`CryptoError::Encoding`] if the byte length is wrong, or
    /// [`CryptoError::InvalidKey`] if the key fails FIPS 203 §7.2 validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: ml_kem::Key<EncapsulationKey<MlKem1024Params>> =
            bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        EncapsulationKey::<MlKem1024Params>::new(&arr)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl DecapKey1024 {
    /// Decapsulate `ct`, recovering the shared key.
    #[must_use = "result must be checked"]
    pub fn decapsulate(&self, ct: &Ciphertext1024) -> Result<SharedSecret, CryptoError> {
        let ss = self.0.decapsulate(&ct.0);
        Ok(SharedSecret::from_ml_kem(ss))
    }

    /// Serialize the decapsulation key to a 64-byte seed.
    #[must_use = "result must be checked"]
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.0
            .to_seed()
            .map(|s| s[..].to_vec())
            .ok_or(CryptoError::Encoding)
    }

    /// Deserialize a decapsulation key from a 64-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: Seed = bytes.try_into().map_err(|_| CryptoError::Encoding)?;
        Ok(Self(DecapsulationKey::<MlKem1024Params>::from_seed(arr)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Kem trait helpers: OS-seeded RNG via OxiRng
// ─────────────────────────────────────────────────────────────────────────────

/// Create an OS-seeded RNG suitable for use with ML-KEM / ML-DSA APIs that
/// require `CryptoRng` (i.e. `TryCryptoRng<Error = Infallible>`).
///
/// `OxiRng` implements `TryCryptoRng` with `Error = CryptoError`.  Wrapping it
/// in [`rand_core::UnwrapErr`] converts it to `CryptoRng` by mapping errors to
/// panics — acceptable here because an OS RNG failure is a fatal system error.
fn kem_os_rng() -> Result<rand_core::UnwrapErr<oxicrypto_rand::OxiRng>, oxicrypto_core::CryptoError>
{
    oxicrypto_rand::OxiRng::new().map(rand_core::UnwrapErr)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Kem trait implementations
// ─────────────────────────────────────────────────────────────────────────────

impl Kem for MlKem512 {
    type DecapKey = DecapKey512;
    type EncapKey = EncapKey512;
    type Ciphertext = Ciphertext512;
    type SharedSecret = SharedSecret;

    fn kem_generate() -> Result<(Self::DecapKey, Self::EncapKey), oxicrypto_core::CryptoError> {
        let mut rng = kem_os_rng()?;
        Ok(MlKem512::generate(&mut rng))
    }

    fn kem_encapsulate(
        ek: &Self::EncapKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), oxicrypto_core::CryptoError> {
        let mut rng = kem_os_rng()?;
        ek.encapsulate(&mut rng)
    }

    fn kem_decapsulate(
        dk: &Self::DecapKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, oxicrypto_core::CryptoError> {
        dk.decapsulate(ct)
    }
}

impl Kem for MlKem768 {
    type DecapKey = DecapKey768;
    type EncapKey = EncapKey768;
    type Ciphertext = Ciphertext768;
    type SharedSecret = SharedSecret;

    fn kem_generate() -> Result<(Self::DecapKey, Self::EncapKey), oxicrypto_core::CryptoError> {
        let mut rng = kem_os_rng()?;
        Ok(MlKem768::generate(&mut rng))
    }

    fn kem_encapsulate(
        ek: &Self::EncapKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), oxicrypto_core::CryptoError> {
        let mut rng = kem_os_rng()?;
        ek.encapsulate(&mut rng)
    }

    fn kem_decapsulate(
        dk: &Self::DecapKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, oxicrypto_core::CryptoError> {
        dk.decapsulate(ct)
    }
}

impl Kem for MlKem1024 {
    type DecapKey = DecapKey1024;
    type EncapKey = EncapKey1024;
    type Ciphertext = Ciphertext1024;
    type SharedSecret = SharedSecret;

    fn kem_generate() -> Result<(Self::DecapKey, Self::EncapKey), oxicrypto_core::CryptoError> {
        let mut rng = kem_os_rng()?;
        Ok(MlKem1024::generate(&mut rng))
    }

    fn kem_encapsulate(
        ek: &Self::EncapKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), oxicrypto_core::CryptoError> {
        let mut rng = kem_os_rng()?;
        ek.encapsulate(&mut rng)
    }

    fn kem_decapsulate(
        dk: &Self::DecapKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, oxicrypto_core::CryptoError> {
        dk.decapsulate(ct)
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

    #[test]
    fn mlkem512_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0x10u8; 32]);
        let (dk, ek) = MlKem512::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem768_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0x20u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem1024_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0x30u8; 32]);
        let (dk, ek) = MlKem1024::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn shared_key_is_32_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0x40u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice().len(), 32);
        assert_eq!(ss_dec.as_slice().len(), 32);
    }

    // ── new: Zeroize ──────────────────────────────────────────────────────────

    #[test]
    fn shared_key_pq_zeroize_compiles() {
        let mut rng = ChaCha20Rng::from_seed([0x50u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let mut ss = dk.decapsulate(&ct).expect("decapsulate failed");
        ss.zeroize();
        // After zeroize, the bytes must all be zero.
        assert!(ss.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn shared_key_pq_debug_does_not_leak() {
        let mut rng = ChaCha20Rng::from_seed([0x51u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss = dk.decapsulate(&ct).expect("decapsulate failed");
        let dbg = format!("{ss:?}");
        // Must not contain any hex-looking byte dump.
        assert!(dbg.contains("***"), "Debug must mask the key bytes");
    }

    // ── new: serialization ────────────────────────────────────────────────────

    #[test]
    fn mlkem512_encapkey_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x60u8; 32]);
        let (dk_orig, ek_orig) = MlKem512::generate(&mut rng);

        // Round-trip the encapsulation key.
        let ek_bytes = ek_orig.to_bytes();
        let ek2 = EncapKey512::from_bytes(&ek_bytes).expect("from_bytes failed");

        // Use the deserialized key to encapsulate; original decap key must recover it.
        let (ct, ss_enc) = ek2.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk_orig.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem512_decapkey_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x61u8; 32]);
        let (dk_orig, ek) = MlKem512::generate(&mut rng);

        // Encapsulate with the original encap key.
        let (ct, ss_orig) = ek.encapsulate(&mut rng).expect("encapsulate failed");

        // Round-trip the decapsulation key via seed bytes.
        let dk_bytes = dk_orig.to_bytes().expect("to_bytes failed");
        assert_eq!(dk_bytes.len(), 64, "ML-KEM-512 decap seed must be 64 bytes");

        let dk2 = DecapKey512::from_bytes(&dk_bytes).expect("from_bytes failed");
        let ss_dec = dk2.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_orig.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem768_encapkey_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x62u8; 32]);
        let (dk_orig, ek_orig) = MlKem768::generate(&mut rng);

        let ek_bytes = ek_orig.to_bytes();
        let ek2 = EncapKey768::from_bytes(&ek_bytes).expect("from_bytes failed");

        let (ct, ss_enc) = ek2.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk_orig.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem768_decapkey_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x63u8; 32]);
        let (dk_orig, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_orig) = ek.encapsulate(&mut rng).expect("encapsulate failed");

        let dk_bytes = dk_orig.to_bytes().expect("to_bytes failed");
        assert_eq!(dk_bytes.len(), 64, "ML-KEM-768 decap seed must be 64 bytes");

        let dk2 = DecapKey768::from_bytes(&dk_bytes).expect("from_bytes failed");
        let ss_dec = dk2.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_orig.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem1024_encapkey_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x64u8; 32]);
        let (dk_orig, ek_orig) = MlKem1024::generate(&mut rng);

        let ek_bytes = ek_orig.to_bytes();
        let ek2 = EncapKey1024::from_bytes(&ek_bytes).expect("from_bytes failed");

        let (ct, ss_enc) = ek2.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk_orig.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem1024_decapkey_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([0x65u8; 32]);
        let (dk_orig, ek) = MlKem1024::generate(&mut rng);
        let (ct, ss_orig) = ek.encapsulate(&mut rng).expect("encapsulate failed");

        let dk_bytes = dk_orig.to_bytes().expect("to_bytes failed");
        assert_eq!(
            dk_bytes.len(),
            64,
            "ML-KEM-1024 decap seed must be 64 bytes"
        );

        let dk2 = DecapKey1024::from_bytes(&dk_bytes).expect("from_bytes failed");
        let ss_dec = dk2.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_orig.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn decapkey_from_bytes_wrong_length_fails() {
        assert!(DecapKey768::from_bytes(&[0u8; 32]).is_err());
        assert!(DecapKey768::from_bytes(&[0u8; 63]).is_err());
        assert!(DecapKey768::from_bytes(&[0u8; 65]).is_err());
    }

    #[test]
    fn encapkey_from_bytes_wrong_length_fails() {
        assert!(EncapKey768::from_bytes(&[0u8; 32]).is_err());
    }

    // ── SA-3: size constants ──────────────────────────────────────────────────

    #[test]
    fn test_mlkem_key_size_constants() {
        assert_eq!(MlKem512::ENCAP_KEY_LEN, 800);
        assert_eq!(MlKem512::DECAP_KEY_LEN, 1632);
        assert_eq!(MlKem512::CIPHERTEXT_LEN, 768);
        assert_eq!(MlKem512::SHARED_SECRET_LEN, 32);

        assert_eq!(MlKem768::ENCAP_KEY_LEN, 1184);
        assert_eq!(MlKem768::DECAP_KEY_LEN, 2400);
        assert_eq!(MlKem768::CIPHERTEXT_LEN, 1088);
        assert_eq!(MlKem768::SHARED_SECRET_LEN, 32);

        assert_eq!(MlKem1024::ENCAP_KEY_LEN, 1568);
        assert_eq!(MlKem1024::DECAP_KEY_LEN, 3168);
        assert_eq!(MlKem1024::CIPHERTEXT_LEN, 1568);
        assert_eq!(MlKem1024::SHARED_SECRET_LEN, 32);
    }

    #[test]
    fn test_encapkey_to_bytes_matches_constant() {
        let mut rng = ChaCha20Rng::from_seed([0xA0u8; 32]);
        let (_, ek512) = MlKem512::generate(&mut rng);
        let (_, ek768) = MlKem768::generate(&mut rng);
        let (_, ek1024) = MlKem1024::generate(&mut rng);
        assert_eq!(ek512.to_bytes().len(), MlKem512::ENCAP_KEY_LEN);
        assert_eq!(ek768.to_bytes().len(), MlKem768::ENCAP_KEY_LEN);
        assert_eq!(ek1024.to_bytes().len(), MlKem1024::ENCAP_KEY_LEN);
    }

    // ── SA-3: SharedKeyPq PartialEq (constant-time) ───────────────────────────

    #[test]
    fn test_shared_key_pq_partial_eq() {
        let mut rng = ChaCha20Rng::from_seed([0xB0u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        // Same key must compare equal.
        assert_eq!(
            ss_enc, ss_dec,
            "encap and decap shared secrets must be equal"
        );

        // A second encapsulation produces a different shared secret.
        let (_, ss_other) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        assert_ne!(
            ss_enc, ss_other,
            "two independent encapsulations must differ"
        );
    }

    // ── SA-3: Debug impls ─────────────────────────────────────────────────────

    #[test]
    fn test_debug_does_not_contain_key_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0xC0u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _) = ek.encapsulate(&mut rng).expect("encapsulate failed");

        let ek_dbg = format!("{ek:?}");
        let dk_dbg = format!("{dk:?}");
        let ct_dbg = format!("{ct:?}");

        // Must mention the type and byte count, must NOT dump raw hex bytes.
        assert!(
            ek_dbg.contains("EncapKey768"),
            "EncapKey768 debug missing type name"
        );
        assert!(
            ek_dbg.contains("bytes"),
            "EncapKey768 debug missing 'bytes'"
        );
        assert!(
            dk_dbg.contains("DecapKey768"),
            "DecapKey768 debug missing type name"
        );
        assert!(
            ct_dbg.contains("Ciphertext768"),
            "Ciphertext768 debug missing type name"
        );

        // Raw key material must not appear.  A generated key contains non-ASCII, but its
        // hex representation would contain extended ASCII runs; the easiest heuristic is
        // that the debug string contains no 0x-hex tokens longer than 4 digits.
        let hex_run: bool = ek_dbg
            .split_whitespace()
            .any(|tok| tok.len() > 6 && tok.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hex_run, "EncapKey768 debug must not dump raw hex bytes");
    }

    #[test]
    fn test_debug_size_annotations_correct() {
        let mut rng = ChaCha20Rng::from_seed([0xC1u8; 32]);
        let (_, ek512) = MlKem512::generate(&mut rng);
        let (_, ek768) = MlKem768::generate(&mut rng);
        let (_, ek1024) = MlKem1024::generate(&mut rng);

        let d512 = format!("{ek512:?}");
        let d768 = format!("{ek768:?}");
        let d1024 = format!("{ek1024:?}");

        assert!(
            d512.contains("800"),
            "EncapKey512 debug must show 800 bytes"
        );
        assert!(
            d768.contains("1184"),
            "EncapKey768 debug must show 1184 bytes"
        );
        assert!(
            d1024.contains("1568"),
            "EncapKey1024 debug must show 1568 bytes"
        );
    }

    // ── SA-3: FIPS 203 §7.2 encap key validation ─────────────────────────────

    #[test]
    fn encapkey_from_bytes_all_ff_is_invalid_key() {
        // 0xFF bytes have coefficients >= q=3329, so they must fail FIPS 203 §7.2 modulus check.
        let bad = vec![0xFFu8; MlKem768::ENCAP_KEY_LEN];
        let result = EncapKey768::from_bytes(&bad);
        assert!(
            matches!(result, Err(CryptoError::InvalidKey)),
            "all-0xFF encap key must return InvalidKey, got: {result:?}"
        );
    }

    #[test]
    fn encapkey_from_bytes_wrong_length_is_encoding_error() {
        // Wrong length should still return Encoding (not InvalidKey).
        let result = EncapKey768::from_bytes(&[0u8; 100]);
        assert!(
            matches!(result, Err(CryptoError::Encoding)),
            "wrong-length encap key must return Encoding, got: {result:?}"
        );
    }
}
