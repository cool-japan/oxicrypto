use crate::CryptoError;

/// Key Encapsulation Mechanism (KEM) primitive.
///
/// Associated types avoid the `dyn Kem` limitation while keeping
/// the interface clean for concrete dispatch.
pub trait Kem {
    /// Public encapsulation key.
    type EncapKey;
    /// Private decapsulation key.
    type DecapKey;
    /// Ciphertext produced by encapsulation.
    type Ciphertext;
    /// Shared secret produced by both parties.
    type SharedSecret: AsRef<[u8]>;

    /// Generate a fresh key pair.  Implementations seed their own RNG.
    #[must_use = "result must be checked"]
    fn kem_generate() -> Result<(Self::DecapKey, Self::EncapKey), CryptoError>;
    /// Encapsulate: produce a ciphertext and shared secret under `ek`.
    #[must_use = "result must be checked"]
    fn kem_encapsulate(
        ek: &Self::EncapKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError>;
    /// Decapsulate: recover the shared secret from `ct` using `dk`.
    #[must_use = "result must be checked"]
    fn kem_decapsulate(
        dk: &Self::DecapKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError>;
}
