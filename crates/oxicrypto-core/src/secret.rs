#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

// ---------------------------------------------------------------------------
// SecretKey<N> -- fixed-size secret with zeroize-on-drop
// ---------------------------------------------------------------------------

/// A fixed-size secret key that is automatically zeroed when dropped.
///
/// `SecretKey<N>` wraps a `[u8; N]` and implements [`Zeroize`] +
/// [`ZeroizeOnDrop`], ensuring that key material does not linger in memory
/// after the value goes out of scope.
///
/// # Examples
///
/// ```
/// use oxicrypto_core::SecretKey;
///
/// let key = SecretKey::<32>::from_slice(&[0xAA; 32]).expect("wrong length");
/// assert_eq!(key.as_bytes().len(), 32);
/// // key is zeroed automatically when dropped
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretKey<N> {
    /// Create a `SecretKey` from a raw byte array.
    #[must_use]
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Create a `SecretKey` from a byte slice.
    ///
    /// Returns [`CryptoError::InvalidKey`] if `slice.len() != N`.
    #[must_use = "result must be checked"]
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; N] = slice.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { bytes })
    }

    /// Borrow the secret bytes.
    ///
    /// Callers should take care not to log or persist this value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> core::fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey<{N}>(***)")
    }
}

impl<const N: usize> Clone for SecretKey<N> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

// ---------------------------------------------------------------------------
// SecretVec -- heap-allocated variable-length secret with zeroize-on-drop
// ---------------------------------------------------------------------------

/// A heap-allocated, variable-length secret that is automatically zeroed
/// when dropped.
///
/// Use `SecretVec` when the key length is not known at compile time (e.g.
/// RSA private keys, derived key material of arbitrary length).
#[cfg(feature = "alloc")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SecretVec {
    /// Create a `SecretVec` from a `Vec<u8>`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create a `SecretVec` by copying from a slice.
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            bytes: slice.to_vec(),
        }
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` if the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretVec(len={}, ***)", self.bytes.len())
    }
}

#[cfg(feature = "alloc")]
impl Clone for SecretVec {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyPair<SK, PK>
// ---------------------------------------------------------------------------

/// A generic key pair bundling a secret key and its corresponding public key.
///
/// The secret half is zeroized when the pair is dropped (via the [`Zeroize`]
/// bound and explicit `Drop` implementation).
pub struct KeyPair<SK: Zeroize, PK> {
    secret: SK,
    public: PK,
}

impl<SK: Zeroize, PK> KeyPair<SK, PK> {
    /// Construct a new key pair.
    #[must_use]
    pub fn new(secret: SK, public: PK) -> Self {
        Self { secret, public }
    }

    /// Borrow the secret key.
    #[must_use]
    pub fn secret(&self) -> &SK {
        &self.secret
    }

    /// Borrow the public key.
    #[must_use]
    pub fn public(&self) -> &PK {
        &self.public
    }
}

impl<SK: Zeroize, PK> Drop for KeyPair<SK, PK> {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl<SK: Zeroize + core::fmt::Debug, PK: core::fmt::Debug> core::fmt::Debug for KeyPair<SK, PK> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("secret", &"***")
            .field("public", &self.public)
            .finish()
    }
}
