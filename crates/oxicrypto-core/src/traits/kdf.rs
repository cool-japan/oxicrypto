use crate::CryptoError;

/// Key derivation function (HKDF, PBKDF2, ...).
pub trait Kdf: Send + Sync {
    /// Human-readable algorithm identifier (e.g. `"HKDF-SHA-256"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Derive key material and write it into `okm_out`.
    ///
    /// - `ikm`: input key material
    /// - `salt`: optional salt (may be empty)
    /// - `info`: context/application-specific info (may be empty)
    #[must_use = "result must be checked"]
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError>;
}

/// Parameters for a password-hashing KDF.
pub trait PasswordHashParams: Send + Sync {
    /// Memory cost in kibibytes (Argon2, scrypt) or `None` if not applicable.
    #[must_use]
    fn memory_cost(&self) -> Option<u32>;
    /// Time cost (iterations for PBKDF2/Argon2) or `None` if not applicable.
    #[must_use]
    fn time_cost(&self) -> Option<u32>;
    /// Degree of parallelism (Argon2/scrypt) or `None` if not applicable.
    #[must_use]
    fn parallelism(&self) -> Option<u32>;
}

/// Password-hashing function (Argon2id, PBKDF2, scrypt, …).
///
/// Distinct from [`Kdf`] because password KDFs expose memory/time/parallelism
/// tuning that is irrelevant for stream KDFs like HKDF.
pub trait PasswordHash: Send + Sync {
    /// Human-readable algorithm identifier (e.g. `"Argon2id"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Hash `password` with `salt` using the given `params`; write output into `out`.
    #[must_use = "result must be checked"]
    fn hash_password(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &dyn PasswordHashParams,
        out: &mut [u8],
    ) -> Result<(), CryptoError>;
}
