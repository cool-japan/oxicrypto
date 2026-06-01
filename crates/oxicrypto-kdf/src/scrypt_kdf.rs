#![forbid(unsafe_code)]

//! Scrypt password-based key derivation for the OxiCrypto stack.
//!
//! Backed by `scrypt` (RustCrypto, Pure Rust).
//! Exposes a low-level interface with explicit N, r, p parameters.

use oxicrypto_core::{CryptoError, PasswordHash as PasswordHashTrait, PasswordHashParams};
use scrypt::{scrypt, Params as RcScryptParams};

// ---------------------------------------------------------------------------
// ScryptParams — our own strongly-typed parameter struct
// ---------------------------------------------------------------------------

/// Parameters for scrypt key derivation.
///
/// RFC 7914 recommends `log_n=14` (N=16384), `r=8`, `p=1` for interactive
/// logins and higher values for sensitive use-cases.
///
/// Note: `log_n` encodes N as log₂(N), e.g. `log_n=14` means N=16384.
#[derive(Debug, Clone, Copy)]
pub struct ScryptParams {
    /// CPU/memory cost factor as log₂(N).  N must be a power of 2.
    pub log_n: u8,
    /// Block size.  RFC 7914 recommends `r=8`.
    pub r: u32,
    /// Parallelization factor.  RFC 7914 recommends `p=1`.
    pub p: u32,
}

impl ScryptParams {
    /// Create new parameters, returning an error if they are invalid.
    #[must_use = "ScryptParams creation result must be checked"]
    pub fn new(log_n: u8, r: u32, p: u32) -> Result<Self, CryptoError> {
        // Validate by constructing the underlying scrypt params.
        RcScryptParams::new(log_n, r, p).map_err(|_| CryptoError::BadInput)?;
        Ok(Self { log_n, r, p })
    }

    /// Interactive login preset.
    ///
    /// N=32768 (log_n=15), r=8, p=1
    /// Provides ≈32 MiB memory and ~100–200 ms on a modern CPU.
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            log_n: 15,
            r: 8,
            p: 1,
        }
    }

    /// Moderate preset — balanced security and speed.
    ///
    /// N=131072 (log_n=17), r=8, p=1
    /// Provides ≈128 MiB memory and ~1 s on a modern CPU.
    #[must_use]
    pub fn moderate() -> Self {
        Self {
            log_n: 17,
            r: 8,
            p: 1,
        }
    }

    /// Sensitive (high-security) preset.
    ///
    /// N=1048576 (log_n=20), r=8, p=1
    /// Provides ≈1 GiB memory and ~5–30 s on a modern CPU.
    #[must_use]
    pub fn sensitive() -> Self {
        Self {
            log_n: 20,
            r: 8,
            p: 1,
        }
    }
}

impl PasswordHashParams for ScryptParams {
    /// Memory cost approximation: 128 × N × r bytes expressed in KiB.
    fn memory_cost(&self) -> Option<u32> {
        // 128 * r * N / 1024 = 128 * r * 2^log_n / 1024
        let n: u64 = 1u64 << self.log_n;
        let kib = 128u64.saturating_mul(n).saturating_mul(self.r as u64) / 1024;
        u32::try_from(kib).ok()
    }

    fn time_cost(&self) -> Option<u32> {
        // scrypt doesn't have a separate time cost; log_n encodes CPU+memory.
        None
    }

    fn parallelism(&self) -> Option<u32> {
        Some(self.p)
    }
}

// ---------------------------------------------------------------------------
// Low-level standalone function (existing API — preserved for compatibility)
// ---------------------------------------------------------------------------

/// Scrypt key derivation.
///
/// # Arguments
/// - `password` — secret password bytes
/// - `salt`     — random salt
/// - `log_n`    — CPU/memory cost factor as log2(N); N must be a power of 2.
///   RFC 7914 §2 uses N=1024 (log_n=10) for interactive logins.
/// - `r`        — block size (RFC 7914 recommends r=8)
/// - `p`        — parallelisation factor (RFC 7914 recommends p=1)
/// - `out`      — output buffer (any length > 0)
#[must_use = "scrypt derive result must be checked"]
pub fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    let params = RcScryptParams::new(log_n, r, p).map_err(|_| CryptoError::BadInput)?;
    scrypt(password, salt, &params, out).map_err(|_| CryptoError::Internal("scrypt failed"))
}

// ---------------------------------------------------------------------------
// ScryptHasher — implements the `PasswordHash` trait from `oxicrypto-core`
// ---------------------------------------------------------------------------

/// A scrypt password hasher that bundles its own cost parameters.
///
/// Implements [`PasswordHash`](oxicrypto_core::PasswordHash) so it can be
/// used polymorphically with [`crate::verify_password`].
///
/// # Design note — `params` argument is ignored
/// The [`PasswordHash::hash_password`](oxicrypto_core::PasswordHash::hash_password)
/// trait method accepts a `params: &dyn PasswordHashParams` argument, but this
/// implementation ignores it and uses `self.params` instead. Callers that
/// need different scrypt parameters should construct a new `ScryptHasher`
/// with the desired `ScryptParams` rather than passing a different
/// `PasswordHashParams` object.
#[derive(Debug, Clone, Copy)]
pub struct ScryptHasher {
    /// Scrypt cost parameters.
    pub params: ScryptParams,
}

impl ScryptHasher {
    /// Create a new hasher with explicit parameters.
    ///
    /// Returns an error if the parameters are out of range.
    pub fn new(params: ScryptParams) -> Result<Self, CryptoError> {
        // Validate params eagerly.
        RcScryptParams::new(params.log_n, params.r, params.p).map_err(|_| CryptoError::BadInput)?;
        Ok(Self { params })
    }

    /// Create a new hasher, panicking if params are invalid.
    ///
    /// Prefer [`ScryptHasher::new`] in production code.
    pub fn new_checked(params: ScryptParams) -> Self {
        Self::new(params).expect("invalid ScryptParams")
    }

    /// Interactive login preset.
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            params: ScryptParams::interactive(),
        }
    }

    /// Moderate (balanced) preset.
    #[must_use]
    pub fn moderate() -> Self {
        Self {
            params: ScryptParams::moderate(),
        }
    }

    /// Sensitive (high-security) preset.
    #[must_use]
    pub fn sensitive() -> Self {
        Self {
            params: ScryptParams::sensitive(),
        }
    }
}

impl PasswordHashTrait for ScryptHasher {
    fn name(&self) -> &'static str {
        "scrypt"
    }

    fn hash_password(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &dyn PasswordHashParams,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        scrypt_derive(
            password,
            salt,
            self.params.log_n,
            self.params.r,
            self.params.p,
            out,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use very small scrypt params so tests complete quickly.
    fn test_params() -> ScryptParams {
        ScryptParams {
            log_n: 1,
            r: 1,
            p: 1,
        }
    }

    fn test_hasher() -> ScryptHasher {
        ScryptHasher::new(test_params()).expect("test params valid")
    }

    const SALT: &[u8] = b"test-salt-16byte";

    #[test]
    fn scrypt_derive_deterministic() {
        let p = test_params();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        scrypt_derive(b"password", SALT, p.log_n, p.r, p.p, &mut out1).expect("derive 1");
        scrypt_derive(b"password", SALT, p.log_n, p.r, p.p, &mut out2).expect("derive 2");
        assert_eq!(out1, out2, "scrypt must be deterministic");
        assert_ne!(out1, [0u8; 32]);
    }

    #[test]
    fn scrypt_derive_empty_output_errors() {
        let p = test_params();
        let result = scrypt_derive(b"password", SALT, p.log_n, p.r, p.p, &mut []);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn password_hash_trait_deterministic() {
        let hasher = test_hasher();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hasher
            .hash_password(b"password", SALT, &hasher.params, &mut out1)
            .expect("hash 1");
        hasher
            .hash_password(b"password", SALT, &hasher.params, &mut out2)
            .expect("hash 2");
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 32]);
    }

    #[test]
    fn preset_cost_ordering() {
        let interactive = ScryptParams::interactive();
        let moderate = ScryptParams::moderate();
        let sensitive = ScryptParams::sensitive();
        // N increases with preset (log_n is monotone)
        assert!(sensitive.log_n > moderate.log_n);
        assert!(moderate.log_n > interactive.log_n);
        // memory_cost is monotonically increasing
        assert!(sensitive.memory_cost() > moderate.memory_cost());
        assert!(moderate.memory_cost() > interactive.memory_cost());
    }

    #[test]
    fn scrypt_params_password_hash_params_impl() {
        let p = ScryptParams::interactive();
        assert!(p.memory_cost().is_some());
        assert!(p.time_cost().is_none());
        assert_eq!(p.parallelism(), Some(1));
    }

    #[test]
    fn hasher_name() {
        assert_eq!(test_hasher().name(), "scrypt");
    }
}
