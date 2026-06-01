use alloc::vec::Vec;

use crate::CryptoError;

/// Diffie-Hellman or similar key-agreement primitive.
pub trait KeyAgreement: Send + Sync {
    /// Human-readable algorithm identifier (e.g. `"X25519"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Length of the scalar (private key) in bytes.
    #[must_use]
    fn scalar_len(&self) -> usize;
    /// Length of the public point in bytes.
    #[must_use]
    fn point_len(&self) -> usize;
    /// Length of the shared secret in bytes.
    ///
    /// Defaults to `self.scalar_len()`, which is correct for all current
    /// implementations (X25519: 32, ECDH P-256: 32, P-384: 48, P-521: 66,
    /// X448: 56).
    #[must_use]
    fn shared_secret_len(&self) -> usize {
        self.scalar_len()
    }
    /// Perform ECDH and write the shared secret into `shared_out`.
    #[must_use = "result must be checked"]
    fn agree(
        &self,
        my_secret: &[u8],
        their_public: &[u8],
        shared_out: &mut [u8],
    ) -> Result<(), CryptoError>;
    /// Convenience: perform ECDH and return the shared secret as a [`Vec<u8>`].
    ///
    /// The output length equals [`shared_secret_len`](KeyAgreement::shared_secret_len).
    #[must_use = "result must be checked"]
    fn agree_to_vec(&self, my_secret: &[u8], their_public: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = alloc::vec![0u8; self.shared_secret_len()];
        self.agree(my_secret, their_public, &mut out)?;
        Ok(out)
    }
}
