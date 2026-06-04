//! Type-safe AEAD nonce wrappers.
//!
//! Use [`Nonce12Bytes`] for 12-byte nonces (AES-GCM, ChaCha20-Poly1305) and
//! [`Nonce24Bytes`] for 24-byte nonces (XChaCha20-Poly1305).

use oxicrypto_core::CryptoError;

/// Type-safe AEAD nonce wrapper.
///
/// Carries a fixed-size nonce array and implements [`core::ops::Deref`] to
/// `[u8]`, so it can be passed directly to any API that takes `&[u8]`.
///
/// # Type aliases
///
/// - [`Nonce12Bytes`] = `NonceBytes<12>` — for AES-GCM and ChaCha20-Poly1305.
/// - [`Nonce24Bytes`] = `NonceBytes<24>` — for XChaCha20-Poly1305.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceBytes<const N: usize>([u8; N]);

impl<const N: usize> NonceBytes<N> {
    /// Wrap a fixed-size nonce array.
    pub const fn from_array(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Access the underlying byte array.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for NonceBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> TryFrom<&[u8]> for NonceBytes<N> {
    type Error = CryptoError;

    fn try_from(slice: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; N] = slice.try_into().map_err(|_| CryptoError::BadInput)?;
        Ok(Self(arr))
    }
}

impl<const N: usize> core::ops::Deref for NonceBytes<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// 12-byte nonce for AES-GCM and ChaCha20-Poly1305.
pub type Nonce12Bytes = NonceBytes<12>;

/// 24-byte nonce for XChaCha20-Poly1305.
pub type Nonce24Bytes = NonceBytes<24>;
