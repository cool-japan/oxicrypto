#![forbid(unsafe_code)]

//! PBKDF2 password-based key derivation for the OxiCrypto stack.
//!
//! Provides PBKDF2-HMAC-SHA-256 and PBKDF2-HMAC-SHA-512 via the
//! `pbkdf2` crate (RustCrypto, digest 0.11 chain).

use oxicrypto_core::{CryptoError, Kdf, PasswordHash as PasswordHashTrait, PasswordHashParams};
use sha2::{Sha256, Sha512};

// ---------------------------------------------------------------------------
// Low-level standalone functions (existing API — preserved for compatibility)
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA-256 key derivation.
///
/// # Arguments
/// - `password`   — secret password bytes
/// - `salt`       — random salt (recommended ≥ 16 bytes)
/// - `iterations` — NIST SP 800-132 recommends ≥ 310_000 for interactive logins
/// - `out`        — output buffer (any length)
#[must_use = "PBKDF2 derive result must be checked"]
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    if iterations == 0 {
        return Err(CryptoError::BadInput);
    }
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, out);
    Ok(())
}

/// PBKDF2-HMAC-SHA-512 key derivation.
#[must_use = "PBKDF2 derive result must be checked"]
pub fn pbkdf2_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    if iterations == 0 {
        return Err(CryptoError::BadInput);
    }
    pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, out);
    Ok(())
}

// ---------------------------------------------------------------------------
// Pbkdf2Params — implements `PasswordHashParams` for the core trait surface
// ---------------------------------------------------------------------------

/// Cost parameters for PBKDF2.
///
/// PBKDF2 has only a time cost (iteration count); there is no memory cost or
/// parallelism parameter.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2Params {
    /// Number of PBKDF2 iterations.
    pub iterations: u32,
}

impl PasswordHashParams for Pbkdf2Params {
    fn memory_cost(&self) -> Option<u32> {
        None
    }

    fn time_cost(&self) -> Option<u32> {
        Some(self.iterations)
    }

    fn parallelism(&self) -> Option<u32> {
        None
    }
}

// ---------------------------------------------------------------------------
// Pbkdf2Sha256Hasher — PasswordHash + Kdf + presets
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA-256 password hasher.
///
/// Implements both [`PasswordHash`](oxicrypto_core::PasswordHash) (for use
/// with [`crate::verify_password`]) and [`Kdf`] (for use as a standard key
/// derivation function).
///
/// # Design note — `params` argument is ignored
/// The [`PasswordHash::hash_password`](oxicrypto_core::PasswordHash::hash_password)
/// trait method accepts a `params: &dyn PasswordHashParams` argument, but this
/// implementation ignores it and uses `self.iterations` instead. Callers that
/// need different iteration counts should construct a new `Pbkdf2Sha256Hasher`
/// with the desired count rather than passing a different `PasswordHashParams` object.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2Sha256Hasher {
    /// Number of PBKDF2 iterations.
    pub iterations: u32,
}

impl Pbkdf2Sha256Hasher {
    /// Create a new hasher with an explicit iteration count.
    #[must_use]
    pub fn new(iterations: u32) -> Self {
        Self { iterations }
    }

    /// Interactive login preset — 310,000 iterations (NIST SP 800-132 minimum).
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            iterations: 310_000,
        }
    }

    /// Moderate preset — 600,000 iterations (OWASP 2024 recommendation).
    #[must_use]
    pub fn moderate() -> Self {
        Self {
            iterations: 600_000,
        }
    }

    /// Sensitive (high-security) preset — 1,000,000 iterations.
    #[must_use]
    pub fn sensitive() -> Self {
        Self {
            iterations: 1_000_000,
        }
    }

    /// Return the cost parameters as a [`Pbkdf2Params`].
    #[must_use]
    pub fn params(&self) -> Pbkdf2Params {
        Pbkdf2Params {
            iterations: self.iterations,
        }
    }
}

impl PasswordHashTrait for Pbkdf2Sha256Hasher {
    fn name(&self) -> &'static str {
        "pbkdf2-sha256"
    }

    fn hash_password(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &dyn PasswordHashParams,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        pbkdf2_sha256(password, salt, self.iterations, out)
    }
}

impl Kdf for Pbkdf2Sha256Hasher {
    fn name(&self) -> &'static str {
        "PBKDF2-SHA-256"
    }

    /// Derive key material from a password (IKM) and salt.
    ///
    /// The `info` argument is not used by PBKDF2 (it has no native concept of
    /// application-specific context); pass an empty slice.
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        _info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        pbkdf2_sha256(ikm, salt, self.iterations, okm_out)
    }
}

// ---------------------------------------------------------------------------
// Pbkdf2Sha512Hasher — PasswordHash + Kdf + presets
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA-512 password hasher.
///
/// Implements both [`PasswordHash`](oxicrypto_core::PasswordHash) and [`Kdf`].
///
/// # Design note — `params` argument is ignored
/// The [`PasswordHash::hash_password`](oxicrypto_core::PasswordHash::hash_password)
/// trait method accepts a `params: &dyn PasswordHashParams` argument, but this
/// implementation ignores it and uses `self.iterations` instead. Callers that
/// need different iteration counts should construct a new `Pbkdf2Sha512Hasher`
/// with the desired count rather than passing a different `PasswordHashParams` object.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2Sha512Hasher {
    /// Number of PBKDF2 iterations.
    pub iterations: u32,
}

impl Pbkdf2Sha512Hasher {
    /// Create a new hasher with an explicit iteration count.
    #[must_use]
    pub fn new(iterations: u32) -> Self {
        Self { iterations }
    }

    /// Interactive login preset — 210,000 iterations (approx. equivalent CPU
    /// cost to 310,000 SHA-256 rounds, per OWASP guidance).
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            iterations: 210_000,
        }
    }

    /// Moderate preset — 400,000 iterations.
    #[must_use]
    pub fn moderate() -> Self {
        Self {
            iterations: 400_000,
        }
    }

    /// Sensitive (high-security) preset — 700,000 iterations.
    #[must_use]
    pub fn sensitive() -> Self {
        Self {
            iterations: 700_000,
        }
    }

    /// Return the cost parameters as a [`Pbkdf2Params`].
    #[must_use]
    pub fn params(&self) -> Pbkdf2Params {
        Pbkdf2Params {
            iterations: self.iterations,
        }
    }
}

impl PasswordHashTrait for Pbkdf2Sha512Hasher {
    fn name(&self) -> &'static str {
        "pbkdf2-sha512"
    }

    fn hash_password(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &dyn PasswordHashParams,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        pbkdf2_sha512(password, salt, self.iterations, out)
    }
}

impl Kdf for Pbkdf2Sha512Hasher {
    fn name(&self) -> &'static str {
        "PBKDF2-SHA-512"
    }

    /// Derive key material from a password (IKM) and salt.
    ///
    /// The `info` argument is not used by PBKDF2; pass an empty slice.
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        _info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        pbkdf2_sha512(ikm, salt, self.iterations, okm_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"test-salt-16byte";
    const ITERS: u32 = 1_000; // Fast for tests

    #[test]
    fn pbkdf2_sha256_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        pbkdf2_sha256(b"password", SALT, ITERS, &mut out1).expect("derive 1");
        pbkdf2_sha256(b"password", SALT, ITERS, &mut out2).expect("derive 2");
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 32]);
    }

    #[test]
    fn pbkdf2_sha512_deterministic() {
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        pbkdf2_sha512(b"password", SALT, ITERS, &mut out1).expect("derive 1");
        pbkdf2_sha512(b"password", SALT, ITERS, &mut out2).expect("derive 2");
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 64]);
    }

    #[test]
    fn pbkdf2_sha256_zero_iterations_errors() {
        let mut out = [0u8; 32];
        assert_eq!(
            pbkdf2_sha256(b"pw", SALT, 0, &mut out),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn pbkdf2_sha256_empty_output_errors() {
        assert_eq!(
            pbkdf2_sha256(b"pw", SALT, ITERS, &mut []),
            Err(CryptoError::BadInput)
        );
    }

    // ── PasswordHash trait ───────────────────────────────────────────────────

    #[test]
    fn pbkdf2_sha256_hasher_hash_password_deterministic() {
        let hasher = Pbkdf2Sha256Hasher::new(ITERS);
        let params = hasher.params();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hasher
            .hash_password(b"password", SALT, &params, &mut out1)
            .expect("hash 1");
        hasher
            .hash_password(b"password", SALT, &params, &mut out2)
            .expect("hash 2");
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 32]);
    }

    #[test]
    fn pbkdf2_sha512_hasher_hash_password_deterministic() {
        let hasher = Pbkdf2Sha512Hasher::new(ITERS);
        let params = hasher.params();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        hasher
            .hash_password(b"password", SALT, &params, &mut out1)
            .expect("hash 1");
        hasher
            .hash_password(b"password", SALT, &params, &mut out2)
            .expect("hash 2");
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 64]);
    }

    // ── Kdf trait ───────────────────────────────────────────────────────────

    #[test]
    fn pbkdf2_sha256_kdf_matches_standalone() {
        let hasher = Pbkdf2Sha256Hasher::new(ITERS);
        let mut from_kdf = [0u8; 32];
        let mut from_fn = [0u8; 32];
        hasher
            .derive(b"key", SALT, b"", &mut from_kdf)
            .expect("kdf derive");
        pbkdf2_sha256(b"key", SALT, ITERS, &mut from_fn).expect("fn derive");
        assert_eq!(from_kdf, from_fn, "Kdf::derive must match standalone fn");
    }

    #[test]
    fn pbkdf2_sha512_kdf_matches_standalone() {
        let hasher = Pbkdf2Sha512Hasher::new(ITERS);
        let mut from_kdf = [0u8; 64];
        let mut from_fn = [0u8; 64];
        hasher
            .derive(b"key", SALT, b"", &mut from_kdf)
            .expect("kdf derive");
        pbkdf2_sha512(b"key", SALT, ITERS, &mut from_fn).expect("fn derive");
        assert_eq!(from_kdf, from_fn, "Kdf::derive must match standalone fn");
    }

    // ── Presets ─────────────────────────────────────────────────────────────

    #[test]
    fn pbkdf2_sha256_preset_cost_ordering() {
        let interactive = Pbkdf2Sha256Hasher::interactive();
        let moderate = Pbkdf2Sha256Hasher::moderate();
        let sensitive = Pbkdf2Sha256Hasher::sensitive();
        assert!(sensitive.iterations > moderate.iterations);
        assert!(moderate.iterations > interactive.iterations);
    }

    #[test]
    fn pbkdf2_sha512_preset_cost_ordering() {
        let interactive = Pbkdf2Sha512Hasher::interactive();
        let moderate = Pbkdf2Sha512Hasher::moderate();
        let sensitive = Pbkdf2Sha512Hasher::sensitive();
        assert!(sensitive.iterations > moderate.iterations);
        assert!(moderate.iterations > interactive.iterations);
    }

    #[test]
    fn pbkdf2_params_trait_impl() {
        let params = Pbkdf2Params { iterations: 42 };
        assert_eq!(params.memory_cost(), None);
        assert_eq!(params.time_cost(), Some(42));
        assert_eq!(params.parallelism(), None);
    }

    #[test]
    fn hasher_names() {
        assert_eq!(
            <Pbkdf2Sha256Hasher as oxicrypto_core::PasswordHash>::name(&Pbkdf2Sha256Hasher::new(1)),
            "pbkdf2-sha256"
        );
        assert_eq!(
            <Pbkdf2Sha512Hasher as oxicrypto_core::PasswordHash>::name(&Pbkdf2Sha512Hasher::new(1)),
            "pbkdf2-sha512"
        );
    }
}
