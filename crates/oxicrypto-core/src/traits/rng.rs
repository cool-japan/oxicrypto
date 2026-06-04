use crate::CryptoError;

/// Cryptographically-secure random number generator.
///
/// When the `debug` Cargo feature is enabled this trait gains `Debug` as a
/// supertrait, enabling `Box<dyn Rng>` to be formatted with `{:?}`.
pub trait Rng: Send + Sync + crate::traits::MaybeDebug {
    /// Fill `dst` with cryptographically secure random bytes.
    #[must_use = "result must be checked"]
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError>;
}
