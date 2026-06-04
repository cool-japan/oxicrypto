use alloc::vec::Vec;

use crate::CryptoError;

/// Message Authentication Code (HMAC, CMAC, KMAC, Poly1305, …).
///
/// # Minimum key lengths
///
/// For security, MAC keys must meet the following minimum lengths.  Passing a
/// key shorter than `min_key_len()` is accepted at the API level (the MAC spec
/// does not mandate rejection) but **reduces the security level significantly**.
///
/// | Algorithm | Minimum recommended key | Notes |
/// |-----------|------------------------|-------|
/// | HMAC-SHA-256 | 32 bytes (= output length) | RFC 2104: key < block-size is padded |
/// | HMAC-SHA-384 | 48 bytes | same rule |
/// | HMAC-SHA-512 | 64 bytes | same rule |
/// | HMAC-SHA3-256/512 | output length | same rule |
/// | CMAC-AES-128 | 16 bytes (exact) | AES block cipher key |
/// | CMAC-AES-256 | 32 bytes (exact) | AES block cipher key |
/// | Poly1305 | 32 bytes (exact) | one-time key; **must not be reused** |
/// | KMAC128 / KMAC256 | 16 bytes | NIST SP 800-185 recommendation |
pub trait Mac: Send + Sync + crate::traits::MaybeDebug {
    /// Human-readable algorithm identifier (e.g. `"HMAC-SHA-256"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Required key length in bytes (the *minimum acceptable* for this MAC).
    ///
    /// For HMAC variants this returns the hash output length.
    /// For CMAC-AES this returns the exact AES key size (16 or 32 bytes).
    /// For Poly1305 this returns 32 (the one-time key size).
    #[must_use]
    fn key_len(&self) -> usize;
    /// Output tag length in bytes.
    #[must_use]
    fn output_len(&self) -> usize;
    /// Compute a MAC tag for `msg` under `key` and write it into `out`.
    #[must_use = "result must be checked"]
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
    /// Verify a MAC tag in constant time.
    ///
    /// Returns [`CryptoError::InvalidTag`] on mismatch.
    #[must_use = "result must be checked"]
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError>;

    /// Minimum recommended key length in bytes.
    ///
    /// Providing a shorter key is accepted but reduces security.
    /// Default returns `self.key_len()` (which for most MACs returns `output_len()`).
    #[must_use]
    fn min_key_len(&self) -> usize {
        self.key_len()
    }

    /// Convenience: compute MAC and return the tag as a [`Vec<u8>`].
    #[must_use = "result must be checked"]
    fn mac_to_vec(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = alloc::vec![0u8; self.output_len()];
        self.mac(key, msg, &mut out)?;
        Ok(out)
    }
}

/// Incremental (streaming) MAC computation.
pub trait StreamingMac: Send {
    /// Feed additional data into the MAC state.
    fn update(&mut self, data: &[u8]);
    /// Consume the MAC state and write the tag into `out`.
    #[must_use = "result must be checked"]
    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError>;
    /// Consume the MAC state, compute the tag, and verify against `expected`
    /// in constant time.
    #[must_use = "result must be checked"]
    fn verify(self, expected: &[u8]) -> Result<(), CryptoError>;
}
