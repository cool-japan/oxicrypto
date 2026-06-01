#![forbid(unsafe_code)]

//! Argon2id password hashing / key derivation for the OxiCrypto stack.
//!
//! Backed by `argon2` (RustCrypto, Pure Rust, digest 0.11 chain).
//! Only the `Argon2id` variant is exposed — it is recommended by RFC 9106 §4.

extern crate alloc;

use alloc::string::String;
use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypto_core::{CryptoError, PasswordHash as PasswordHashTrait, PasswordHashParams};

/// Parameters for Argon2id key derivation.
///
/// RFC 9106 §4 recommends at least `m_cost = 65536` (64 MiB), `t_cost = 3`, `p_cost = 4`
/// for offline use and lower values for interactive contexts.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KiB (must be ≥ 8 × `p_cost`).
    pub m_cost: u32,
    /// Time cost (number of passes over memory).
    pub t_cost: u32,
    /// Parallelism cost (number of lanes).
    pub p_cost: u32,
}

impl Argon2Params {
    /// Minimum parameters suitable for unit tests (fast, not secure for production).
    pub const TEST_PARAMS: Self = Self {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
    };

    /// Validate that parameters meet OWASP 2023 / RFC 9106 minimum requirements.
    ///
    /// Enforces:
    /// - `m_cost >= 19_456` (19 MiB — OWASP 2023 Password Storage Cheat Sheet minimum)
    /// - `t_cost >= 2` (RFC 9106 §4 recommended minimum passes)
    /// - `p_cost >= 1` (at least one lane required)
    /// - `m_cost >= 8 * p_cost` (RFC 9106 §3.1 block-count constraint)
    ///
    /// Note: [`Argon2Params::TEST_PARAMS`] intentionally violates these bounds for
    /// test speed; this method is opt-in and not invoked by [`argon2id_derive`].
    ///
    /// # Errors
    /// Returns [`CryptoError::BadInput`] if any constraint is violated.
    pub fn validate(&self) -> Result<(), CryptoError> {
        // OWASP 2023: memory >= 19 MiB (19 456 KiB)
        if self.m_cost < 19_456 {
            return Err(CryptoError::BadInput);
        }
        // Minimum iteration count (RFC 9106 §4)
        if self.t_cost < 2 {
            return Err(CryptoError::BadInput);
        }
        // At least one lane
        if self.p_cost < 1 {
            return Err(CryptoError::BadInput);
        }
        // RFC 9106 §3.1: m_cost must be >= 8 * p_cost
        if self.m_cost < 8 * self.p_cost {
            return Err(CryptoError::BadInput);
        }
        Ok(())
    }

    /// Interactive login preset (OWASP 2024 / libsodium `OPSLIMIT_INTERACTIVE`).
    ///
    /// m=65536 (64 MiB), t=2, p=1
    /// Provides ~1 s latency on a modern server.
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 2,
            p_cost: 1,
        }
    }

    /// Moderate preset — balanced between interactive and sensitive.
    ///
    /// m=262144 (256 MiB), t=3, p=4
    /// Provides ~2–4 s on a modern server; suitable for non-interactive key derivation.
    #[must_use]
    pub fn moderate() -> Self {
        Self {
            m_cost: 262_144,
            t_cost: 3,
            p_cost: 4,
        }
    }

    /// Sensitive preset (libsodium `OPSLIMIT_SENSITIVE`).
    ///
    /// m=1048576 (1 GiB), t=4, p=8
    /// High-security offline key derivation; only use where latency is acceptable.
    #[must_use]
    pub fn sensitive() -> Self {
        Self {
            m_cost: 1_048_576,
            t_cost: 4,
            p_cost: 8,
        }
    }
}

impl PasswordHashParams for Argon2Params {
    fn memory_cost(&self) -> Option<u32> {
        Some(self.m_cost)
    }

    fn time_cost(&self) -> Option<u32> {
        Some(self.t_cost)
    }

    fn parallelism(&self) -> Option<u32> {
        Some(self.p_cost)
    }
}

/// Argon2id key derivation.
///
/// # Arguments
/// - `password` — secret password bytes
/// - `salt`     — random salt (must be ≥ 8 bytes per the Argon2 spec)
/// - `params`   — Argon2 cost parameters
/// - `out`      — output buffer (1–64 bytes per the spec)
#[must_use = "argon2id derive result must be checked"]
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    if salt.len() < 8 {
        return Err(CryptoError::BadInput);
    }
    let a2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(out.len()))
        .map_err(|_| CryptoError::BadInput)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2_params);
    argon2
        .hash_password_into(password, salt, out)
        .map_err(|_| CryptoError::Internal("Argon2id derive failed"))
}

/// Argon2d (data-dependent memory access) key derivation.
///
/// Argon2d is faster than Argon2id but vulnerable to side-channel attacks from
/// GPU-based memory access timing. Suitable for crypto key derivation contexts
/// where the attacker does not have local access to the machine.
///
/// # Arguments
/// - `password` — secret password bytes
/// - `salt`     — random salt (must be ≥ 8 bytes per the Argon2 spec)
/// - `params`   — Argon2 cost parameters
/// - `out`      — output buffer (1–64 bytes per the spec)
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `out` is empty, `salt.len() < 8`,
/// or the parameter values are out of range.
#[must_use = "argon2d derive result must be checked"]
pub fn argon2d_derive(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    if salt.len() < 8 {
        return Err(CryptoError::BadInput);
    }
    let a2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(out.len()))
        .map_err(|_| CryptoError::BadInput)?;
    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, a2_params);
    argon2
        .hash_password_into(password, salt, out)
        .map_err(|_| CryptoError::Internal("Argon2d derive failed"))
}

/// Argon2i (data-independent memory access) key derivation.
///
/// Argon2i uses data-independent memory access, making it resistant to
/// side-channel attacks. It is weaker against GPU and ASIC attacks than
/// Argon2id, but suitable where side-channel resistance is the primary concern.
///
/// # Arguments
/// - `password` — secret password bytes
/// - `salt`     — random salt (must be ≥ 8 bytes per the Argon2 spec)
/// - `params`   — Argon2 cost parameters
/// - `out`      — output buffer (1–64 bytes per the spec)
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `out` is empty, `salt.len() < 8`,
/// or the parameter values are out of range.
#[must_use = "argon2i derive result must be checked"]
pub fn argon2i_derive(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    if salt.len() < 8 {
        return Err(CryptoError::BadInput);
    }
    let a2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(out.len()))
        .map_err(|_| CryptoError::BadInput)?;
    let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, a2_params);
    argon2
        .hash_password_into(password, salt, out)
        .map_err(|_| CryptoError::Internal("Argon2i derive failed"))
}

// ---------------------------------------------------------------------------
// Argon2idHasher — implements the `PasswordHash` trait from `oxicrypto-core`
// ---------------------------------------------------------------------------

/// An Argon2id password hasher that bundles its own cost parameters.
///
/// Implements [`PasswordHash`](oxicrypto_core::PasswordHash) so it can be
/// used polymorphically with [`crate::verify_password`].
///
/// # Design note
/// The `PasswordHash::hash_password` method from `oxicrypto-core` accepts a
/// `&dyn PasswordHashParams` argument, but `Argon2idHasher` uses its own
/// stored `params` field rather than the external parameter object. This is
/// intentional: Argon2 parameters are typed (`m_cost`/`t_cost`/`p_cost`) and
/// the generic `PasswordHashParams` trait only surfaces them as `Option<u32>`,
/// which is insufficient for safe Argon2 initialization. Callers that need
/// dynamic parameter tuning should construct a new `Argon2idHasher` with the
/// desired `Argon2Params`.
#[derive(Debug, Clone, Copy)]
pub struct Argon2idHasher {
    /// Argon2id cost parameters.
    pub params: Argon2Params,
}

impl Argon2idHasher {
    /// Create a new hasher with explicit parameters.
    #[must_use]
    pub fn new(params: Argon2Params) -> Self {
        Self { params }
    }

    /// Interactive login preset.
    #[must_use]
    pub fn interactive() -> Self {
        Self::new(Argon2Params::interactive())
    }

    /// Moderate (balanced) preset.
    #[must_use]
    pub fn moderate() -> Self {
        Self::new(Argon2Params::moderate())
    }

    /// Sensitive (high-security) preset.
    #[must_use]
    pub fn sensitive() -> Self {
        Self::new(Argon2Params::sensitive())
    }
}

impl PasswordHashTrait for Argon2idHasher {
    fn name(&self) -> &'static str {
        "argon2id"
    }

    fn hash_password(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &dyn PasswordHashParams,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        // Use self.params directly (see design note on Argon2idHasher).
        argon2id_derive(password, salt, self.params, out)
    }
}

// ---------------------------------------------------------------------------
// PHC string support — uses the `argon2` crate's `PasswordHasher` impl
// ---------------------------------------------------------------------------

/// Encode an Argon2id hash as a PHC string.
///
/// Builds the standard `$argon2id$v=19$m=<m>,t=<t>,p=<p>$<b64-salt>$<b64-hash>`
/// string from pre-computed hash bytes and the hasher's parameters.
///
/// `salt` must be ≥ 8 bytes; `hash` must be between
/// [`password_hash::phc::Output::MIN_LENGTH`] and
/// [`password_hash::phc::Output::MAX_LENGTH`] bytes (1–64).
///
/// # Errors
/// - [`CryptoError::BadInput`] — parameter values are out of range.
/// - [`CryptoError::Encoding`] — PHC string assembly failed.
#[must_use = "PHC string result must be checked"]
pub fn argon2id_to_phc_string(
    hasher: &Argon2idHasher,
    salt: &[u8],
    hash: &[u8],
) -> Result<String, CryptoError> {
    use argon2::PasswordHash;
    use password_hash::phc::{Output, ParamsString, Salt};

    // Validate and build argon2 Params so we can convert to ParamsString.
    let a2_params = Params::new(
        hasher.params.m_cost,
        hasher.params.t_cost,
        hasher.params.p_cost,
        Some(hash.len()),
    )
    .map_err(|_| CryptoError::BadInput)?;

    let params_str = ParamsString::try_from(&a2_params).map_err(|_| CryptoError::Encoding)?;

    let salt_val = Salt::new(salt).map_err(|_| CryptoError::BadInput)?;

    let output = Output::new(hash).map_err(|_| CryptoError::Encoding)?;

    let ph = PasswordHash {
        algorithm: argon2::ARGON2ID_IDENT,
        version: Some(Version::V0x13.into()),
        params: params_str,
        salt: Some(salt_val),
        hash: Some(output),
    };

    Ok(alloc::format!("{ph}"))
}

/// Verify a password against an Argon2id PHC string.
///
/// Parses the PHC string, extracts the embedded algorithm parameters, and
/// re-derives the hash in constant time.
///
/// # Errors
/// - [`CryptoError::Encoding`] — malformed PHC string.
/// - [`CryptoError::InvalidTag`] — password does not match.
#[must_use = "PHC verification result must be checked"]
pub fn argon2id_verify_phc(phc: &str, password: &[u8]) -> Result<(), CryptoError> {
    use argon2::{PasswordHash, PasswordVerifier};

    let hash = PasswordHash::new(phc).map_err(|_| CryptoError::Encoding)?;
    Argon2::default()
        .verify_password(password, &hash)
        .map_err(|_| CryptoError::InvalidTag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Use tiny params so tests finish quickly.
    fn test_hasher() -> Argon2idHasher {
        Argon2idHasher::new(Argon2Params::TEST_PARAMS)
    }

    const TEST_SALT: &[u8] = b"01234567890abcde"; // 16 bytes

    #[test]
    fn argon2id_derive_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        argon2id_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut out1)
            .expect("derive 1");
        argon2id_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut out2)
            .expect("derive 2");
        assert_eq!(out1, out2, "Argon2id must be deterministic");
        assert_ne!(out1, [0u8; 32]);
    }

    #[test]
    fn argon2id_derive_short_salt_errors() {
        let mut out = [0u8; 32];
        let result = argon2id_derive(b"password", b"short", Argon2Params::TEST_PARAMS, &mut out);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn argon2id_derive_empty_output_errors() {
        let result = argon2id_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut []);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn password_hash_trait_hash_password_deterministic() {
        let hasher = test_hasher();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hasher
            .hash_password(b"password", TEST_SALT, &hasher.params, &mut out1)
            .expect("hash 1");
        hasher
            .hash_password(b"password", TEST_SALT, &hasher.params, &mut out2)
            .expect("hash 2");
        assert_eq!(out1, out2, "PasswordHash must be deterministic");
        assert_ne!(out1, [0u8; 32]);
    }

    #[test]
    fn preset_cost_ordering() {
        let interactive = Argon2Params::interactive();
        let moderate = Argon2Params::moderate();
        let sensitive = Argon2Params::sensitive();
        // Memory cost: sensitive > moderate > interactive
        assert!(sensitive.m_cost > moderate.m_cost);
        assert!(moderate.m_cost > interactive.m_cost);
        // Time cost: sensitive ≥ moderate ≥ interactive
        assert!(sensitive.t_cost >= moderate.t_cost);
        assert!(moderate.t_cost >= interactive.t_cost);
    }

    #[test]
    fn hasher_name() {
        assert_eq!(test_hasher().name(), "argon2id");
    }

    #[test]
    fn phc_round_trip() {
        let hasher = test_hasher();
        let mut hash = [0u8; 32];
        argon2id_derive(b"password", TEST_SALT, hasher.params, &mut hash).expect("derive");

        let phc = argon2id_to_phc_string(&hasher, TEST_SALT, &hash).expect("to_phc");
        assert!(
            phc.starts_with("$argon2id$"),
            "PHC must start with $argon2id$"
        );

        // Verify with same password: must succeed.
        argon2id_verify_phc(&phc, b"password").expect("verify correct");
    }

    #[test]
    fn phc_wrong_password_rejected() {
        let hasher = test_hasher();
        let mut hash = [0u8; 32];
        argon2id_derive(b"password", TEST_SALT, hasher.params, &mut hash).expect("derive");

        let phc = argon2id_to_phc_string(&hasher, TEST_SALT, &hash).expect("to_phc");
        let result = argon2id_verify_phc(&phc, b"wrongpassword");
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn phc_malformed_string_rejected() {
        let result = argon2id_verify_phc("invalid-phc-string", b"password");
        assert_eq!(result, Err(CryptoError::Encoding));
    }

    // ---------------------------------------------------------------------------
    // Argon2d and Argon2i variant tests
    // ---------------------------------------------------------------------------

    #[test]
    fn argon2d_derive_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        argon2d_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut out1)
            .expect("argon2d derive 1");
        argon2d_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut out2)
            .expect("argon2d derive 2");
        assert_eq!(out1, out2, "Argon2d must be deterministic");
        assert_ne!(out1, [0u8; 32]);
    }

    #[test]
    fn argon2i_derive_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        argon2i_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut out1)
            .expect("argon2i derive 1");
        argon2i_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut out2)
            .expect("argon2i derive 2");
        assert_eq!(out1, out2, "Argon2i must be deterministic");
        assert_ne!(out1, [0u8; 32]);
    }

    /// Verify that all three Argon2 variants (d, i, id) produce distinct outputs
    /// for identical inputs — proving they actually use different algorithm modes.
    #[test]
    fn argon2_variants_produce_distinct_outputs() {
        let mut out_id = [0u8; 32];
        let mut out_d = [0u8; 32];
        let mut out_i = [0u8; 32];
        argon2id_derive(
            b"password",
            TEST_SALT,
            Argon2Params::TEST_PARAMS,
            &mut out_id,
        )
        .expect("argon2id");
        argon2d_derive(
            b"password",
            TEST_SALT,
            Argon2Params::TEST_PARAMS,
            &mut out_d,
        )
        .expect("argon2d");
        argon2i_derive(
            b"password",
            TEST_SALT,
            Argon2Params::TEST_PARAMS,
            &mut out_i,
        )
        .expect("argon2i");
        // All three algorithm variants must produce different derived keys.
        assert_ne!(out_id, out_d, "Argon2id must differ from Argon2d");
        assert_ne!(out_id, out_i, "Argon2id must differ from Argon2i");
        assert_ne!(out_d, out_i, "Argon2d must differ from Argon2i");
    }

    #[test]
    fn argon2d_short_salt_errors() {
        let mut out = [0u8; 32];
        let result = argon2d_derive(b"password", b"short", Argon2Params::TEST_PARAMS, &mut out);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn argon2d_empty_output_errors() {
        let result = argon2d_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut []);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn argon2i_short_salt_errors() {
        let mut out = [0u8; 32];
        let result = argon2i_derive(b"password", b"short", Argon2Params::TEST_PARAMS, &mut out);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn argon2i_empty_output_errors() {
        let result = argon2i_derive(b"password", TEST_SALT, Argon2Params::TEST_PARAMS, &mut []);
        assert_eq!(result, Err(CryptoError::BadInput));
    }
}
