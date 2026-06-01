use crate::CryptoError;

/// Cryptographically-secure random number generator.
pub trait Rng: Send + Sync {
    /// Fill `dst` with cryptographically secure random bytes.
    #[must_use = "result must be checked"]
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError>;
}
