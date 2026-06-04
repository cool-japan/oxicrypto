/// Unified error type for all OxiCrypto operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum CryptoError {
    /// Supplied key has wrong length or is otherwise invalid.
    InvalidKey,
    /// Supplied nonce/IV has wrong length or is otherwise invalid.
    InvalidNonce,
    /// Authentication tag verification failed (AEAD open / MAC verify).
    InvalidTag,
    /// Output buffer is too small for the requested operation.
    BufferTooSmall,
    /// General bad-input condition (e.g. zero-length KDF output requested).
    BadInput,
    /// An internal or backend error with a static message.
    ///
    /// **Serde note:** When deserializing, the `&'static str` payload cannot
    /// be reconstructed from arbitrary data in a `no_std + alloc` crate.
    /// The variant is deserialized as `Internal("")` — the serialized form
    /// preserves the string for observability/logging; round-trip lossiness
    /// is intentional.
    Internal(&'static str),
    /// Key-exchange or encapsulation/decapsulation failure (e.g. ML-KEM).
    Kex,
    /// Signature generation or verification failure (e.g. ML-DSA).
    Sign,
    /// RNG-specific failure (e.g. `getrandom` unavailable).
    Rng,
    /// Encoding / decoding failure (DER, PEM, SEC1, etc.).
    Encoding,
    /// Requested algorithm is not compiled-in or not supported at runtime.
    UnsupportedAlgorithm,
}

// ---------------------------------------------------------------------------
// Manual `Deserialize` implementation
// ---------------------------------------------------------------------------
//
// Derived `Deserialize` would bind lifetime `'de` to the `&'static str` in
// `Internal`, producing `impl Deserialize<'static>` only — unusable with
// most codecs that operate on shorter-lived slices.
//
// Instead we manually implement `Deserialize` as `DeserializeOwned`-compatible:
// the `Internal` variant reads the payload as an owned `String` (then drops it)
// and always reconstructs `Internal("")`.  All other variants contain no
// borrowed data and round-trip exactly.

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CryptoError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Mirror the variant names used by the derived `Serialize`.
        #[derive(serde::Deserialize)]
        #[serde(rename = "CryptoError")]
        enum Repr {
            InvalidKey,
            InvalidNonce,
            InvalidTag,
            BufferTooSmall,
            BadInput,
            /// Payload deserialized as owned String, discarded afterward.
            Internal(#[allow(dead_code)] alloc::string::String),
            Kex,
            Sign,
            Rng,
            Encoding,
            UnsupportedAlgorithm,
        }

        let repr = Repr::deserialize(deserializer)?;
        Ok(match repr {
            Repr::InvalidKey => CryptoError::InvalidKey,
            Repr::InvalidNonce => CryptoError::InvalidNonce,
            Repr::InvalidTag => CryptoError::InvalidTag,
            Repr::BufferTooSmall => CryptoError::BufferTooSmall,
            Repr::BadInput => CryptoError::BadInput,
            // String payload is intentionally discarded; &'static str
            // cannot be reconstructed from deserialized data without unsafe.
            Repr::Internal(_) => CryptoError::Internal(""),
            Repr::Kex => CryptoError::Kex,
            Repr::Sign => CryptoError::Sign,
            Repr::Rng => CryptoError::Rng,
            Repr::Encoding => CryptoError::Encoding,
            Repr::UnsupportedAlgorithm => CryptoError::UnsupportedAlgorithm,
        })
    }
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidKey => write!(f, "invalid key"),
            CryptoError::InvalidNonce => write!(f, "invalid nonce"),
            CryptoError::InvalidTag => write!(f, "invalid authentication tag"),
            CryptoError::BufferTooSmall => write!(f, "output buffer too small"),
            CryptoError::BadInput => write!(f, "bad input"),
            CryptoError::Internal(msg) => write!(f, "internal error: {msg}"),
            CryptoError::Kex => write!(f, "key exchange or encapsulation failure"),
            CryptoError::Sign => write!(f, "signature generation or verification failure"),
            CryptoError::Rng => write!(f, "random number generator failure"),
            CryptoError::Encoding => write!(f, "encoding or decoding failure"),
            CryptoError::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
        }
    }
}

// `core::error::Error` is stable since Rust 1.81; implement it unconditionally
// so that `CryptoError` satisfies bounds like `rand_core::TryRng::Error`
// which require `core::error::Error` regardless of the `std` feature.
// Note: `std::error::Error` re-exports `core::error::Error` in Rust 1.81+,
// so we only implement it once here rather than separately for each gate.
impl core::error::Error for CryptoError {}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl From<CryptoError> for std::io::Error {
    fn from(e: CryptoError) -> Self {
        std::io::Error::other(alloc::format!("{e}"))
    }
}
