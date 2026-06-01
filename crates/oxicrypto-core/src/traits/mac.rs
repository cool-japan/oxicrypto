use alloc::vec::Vec;

use crate::CryptoError;

/// Message Authentication Code (HMAC, ...).
pub trait Mac: Send + Sync {
    /// Human-readable algorithm identifier (e.g. `"HMAC-SHA-256"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Required key length (minimum acceptable length; MACs are often variable).
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
