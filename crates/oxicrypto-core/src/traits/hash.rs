use alloc::vec::Vec;

use crate::CryptoError;

/// Stateless hash function (SHA-2, SHA-3, BLAKE3, ...).
pub trait Hash: Send + Sync {
    /// Human-readable algorithm identifier (e.g. `"SHA-256"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Byte length of the digest output.
    #[must_use]
    fn output_len(&self) -> usize;
    /// Hash `msg` and write the digest into `out`.
    ///
    /// Returns [`CryptoError::BufferTooSmall`] when `out.len() < self.output_len()`.
    #[must_use = "result must be checked"]
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
    /// Convenience: hash `msg` and return the digest as a [`Vec<u8>`].
    #[must_use = "result must be checked"]
    fn hash_to_vec(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = alloc::vec![0u8; self.output_len()];
        self.hash(msg, &mut out)?;
        Ok(out)
    }
    /// Convenience: hash `msg` and return the digest as a fixed-size array.
    ///
    /// Returns [`CryptoError::BadInput`] if `N != self.output_len()`.
    ///
    /// This method requires `Self: Sized` to preserve `dyn Hash` object safety
    /// (const-generic methods cannot be called on trait objects).
    #[must_use = "result must be checked"]
    fn hash_to_array<const N: usize>(&self, msg: &[u8]) -> Result<[u8; N], CryptoError>
    where
        Self: Sized,
    {
        if N != self.output_len() {
            return Err(CryptoError::BadInput);
        }
        let mut out = [0u8; N];
        self.hash(msg, &mut out)?;
        Ok(out)
    }
}

/// Incremental (streaming) hash computation.
///
/// Feed data in chunks with [`update`](StreamingHash::update), then call
/// [`finalize`](StreamingHash::finalize) to obtain the digest.
pub trait StreamingHash: Send {
    /// Feed additional data into the hash state.
    fn update(&mut self, data: &[u8]);
    /// Consume the hasher and write the final digest into `out`.
    ///
    /// Returns [`CryptoError::BufferTooSmall`] if `out` is too short.
    #[must_use = "result must be checked"]
    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError>;
    /// Reset the hasher to its initial state, allowing reuse.
    fn reset(&mut self);
}
