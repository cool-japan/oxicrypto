use crate::CryptoError;

/// Key derivation function (HKDF, PBKDF2, …).
///
/// # Minimum key / input lengths
///
/// | Algorithm | IKM minimum | Notes |
/// |-----------|------------|-------|
/// | HKDF-SHA-{256,384,512} | 1 byte (any non-empty IKM) | Salt and info may be empty |
/// | PBKDF2-SHA-256/512 | 1 byte | Iteration count ≥ 600 000 (SHA-256) or 210 000 (SHA-512) per OWASP 2023 |
/// | Argon2id | 1 byte password, ≥ 8 bytes salt | Per RFC 9106 §4 |
/// | scrypt | 1 byte password | Salt recommended ≥ 16 bytes |
/// | KBKDF (SP 800-108) | 1 byte | PRK derived from a prior HMAC step |
///
/// The maximum output length for HKDF-SHA-256 is **255 × 32 = 8 160 bytes**;
/// for HKDF-SHA-512 it is **255 × 64 = 16 320 bytes**.  Requesting more returns
/// [`CryptoError::Internal`].
pub trait Kdf: Send + Sync + crate::traits::MaybeDebug {
    /// Human-readable algorithm identifier (e.g. `"HKDF-SHA-256"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Derive key material and write it into `okm_out`.
    ///
    /// - `ikm`: input key material (must be non-empty for most algorithms)
    /// - `salt`: optional salt (may be empty; HKDF uses a zero-filled salt of hash length)
    /// - `info`: context/application-specific info (may be empty)
    /// - `okm_out`: output buffer (length must be ≥ 1 and within the algorithm's limit)
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
pub trait PasswordHashParams: Send + Sync + crate::traits::MaybeDebug {
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
pub trait PasswordHash: Send + Sync + crate::traits::MaybeDebug {
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
