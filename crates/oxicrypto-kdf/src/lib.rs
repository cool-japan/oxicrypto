#![forbid(unsafe_code)]

//! Pure Rust KDF implementations for the OxiCrypto stack.
//!
//! | Function | Module | Backend |
//! |----------|--------|---------|
//! | HKDF-SHA-256 / SHA-512 | (inline) | `hkdf` |
//! | HKDF-Expand-Label (TLS 1.3 / QUIC) | [`hkdf_label`] | `hkdf` |
//! | PBKDF2-SHA-256 / SHA-512 | [`pbkdf2_kdf`] | `pbkdf2` |
//! | Argon2id | [`argon2_kdf`] | `argon2` |
//! | scrypt | [`scrypt_kdf`] | `scrypt` |
//! | Balloon (SHA-256 / SHA-512) | [`balloon`] | `sha2` |

pub mod argon2_kdf;
pub mod balloon;
pub mod hkdf_label;
pub mod kbkdf;
pub mod pbkdf2_kdf;
pub mod scrypt_kdf;
pub mod stretcher;

// ── OWASP 2023 minimum iteration counts ───────────────────────────────────────

/// OWASP 2023 Password Storage Cheat Sheet minimum iteration count for
/// PBKDF2-HMAC-SHA-256.
///
/// Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
pub const PBKDF2_SHA256_MIN_ITERATIONS: u32 = 600_000;

/// OWASP 2023 Password Storage Cheat Sheet minimum iteration count for
/// PBKDF2-HMAC-SHA-512.
///
/// SHA-512 is ~2× faster than SHA-256 per round on 64-bit CPUs, so the
/// equivalent minimum is approximately 210,000.
pub const PBKDF2_SHA512_MIN_ITERATIONS: u32 = 210_000;

pub use argon2_kdf::{
    argon2d_derive, argon2i_derive, argon2id_derive, argon2id_to_phc_string, argon2id_verify_phc,
    Argon2Params, Argon2idHasher,
};
pub use balloon::{
    balloon_sha256, balloon_sha256_secret, balloon_sha512, balloon_sha512_secret, BalloonHasher,
    BalloonParams, BalloonVariant, BALLOON_DELTA,
};
pub use hkdf_label::{hkdf_expand_label_sha256, hkdf_expand_label_sha384};
pub use kbkdf::{
    kbkdf_counter_hmac_sha256, kbkdf_counter_hmac_sha256_secret, kbkdf_counter_hmac_sha384,
    kbkdf_counter_hmac_sha512,
};
pub use pbkdf2_kdf::{
    pbkdf2_sha256, pbkdf2_sha512, Pbkdf2Params, Pbkdf2Sha256Hasher, Pbkdf2Sha512Hasher,
};
pub use scrypt_kdf::{scrypt_derive, ScryptHasher, ScryptParams};
pub use stretcher::{
    Argon2idStretchParams, BalloonStretchParams, KeyStretcher, Pbkdf2StretchParams,
    ScryptStretchParams, StretchParams, Stretcher,
};

use hkdf::Hkdf;
use oxicrypto_core::{CryptoError, Kdf, PasswordHash};
use subtle::ConstantTimeEq;

// ── HKDF-SHA-256 ──────────────────────────────────────────────────────────────

/// HKDF-SHA-256 key derivation function.
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfSha256;

impl Kdf for HkdfSha256 {
    fn name(&self) -> &'static str {
        "HKDF-SHA-256"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if okm_out.is_empty() {
            return Err(CryptoError::BadInput);
        }
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let hk = Hkdf::<sha2::Sha256>::new(salt_opt, ikm);
        hk.expand(info, okm_out)
            .map_err(|_| CryptoError::Internal("HKDF expand failed (output too long)"))?;
        Ok(())
    }
}

// ── HKDF-SHA-512 ──────────────────────────────────────────────────────────────

/// HKDF-SHA-512 key derivation function.
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfSha512;

impl Kdf for HkdfSha512 {
    fn name(&self) -> &'static str {
        "HKDF-SHA-512"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if okm_out.is_empty() {
            return Err(CryptoError::BadInput);
        }
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let hk = Hkdf::<sha2::Sha512>::new(salt_opt, ikm);
        hk.expand(info, okm_out)
            .map_err(|_| CryptoError::Internal("HKDF expand failed (output too long)"))?;
        Ok(())
    }
}

// ── HKDF-SHA-384 ──────────────────────────────────────────────────────────────

/// HKDF-SHA-384 key derivation function.
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfSha384;

impl Kdf for HkdfSha384 {
    fn name(&self) -> &'static str {
        "HKDF-SHA-384"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if okm_out.is_empty() {
            return Err(CryptoError::BadInput);
        }
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let hk = Hkdf::<sha2::Sha384>::new(salt_opt, ikm);
        hk.expand(info, okm_out)
            .map_err(|_| CryptoError::Internal("HKDF-SHA-384 expand failed (output too long)"))?;
        Ok(())
    }
}

// ── HKDF Extract-only / Expand-only (RFC 5869 separated phases) ─────────────

/// Perform HKDF-Extract with SHA-256, returning the pseudorandom key (PRK).
///
/// This is the extraction phase only (RFC 5869 Section 2.2).
/// The PRK is always 32 bytes (the output size of SHA-256).
///
/// Used by protocols like TLS 1.3 that need separated extract/expand.
#[must_use]
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<sha2::Sha256>::extract(salt_opt, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// Perform HKDF-Expand with SHA-256 from a pre-extracted PRK.
///
/// This is the expansion phase only (RFC 5869 Section 2.3).
/// `prk` should be the output of [`hkdf_sha256_extract`] (32 bytes).
#[must_use = "HKDF expand result must be checked"]
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], okm_out: &mut [u8]) -> Result<(), CryptoError> {
    if okm_out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    let hk = Hkdf::<sha2::Sha256>::from_prk(prk).map_err(|_| CryptoError::InvalidKey)?;
    hk.expand(info, okm_out)
        .map_err(|_| CryptoError::Internal("HKDF-SHA-256 expand failed (output too long)"))?;
    Ok(())
}

/// Perform HKDF-Extract with SHA-384, returning the pseudorandom key (PRK).
///
/// The PRK is always 48 bytes (the output size of SHA-384).
#[must_use]
pub fn hkdf_sha384_extract(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<sha2::Sha384>::extract(salt_opt, ikm);
    let mut out = [0u8; 48];
    out.copy_from_slice(&prk);
    out
}

/// Perform HKDF-Expand with SHA-384 from a pre-extracted PRK.
#[must_use = "HKDF expand result must be checked"]
pub fn hkdf_sha384_expand(prk: &[u8], info: &[u8], okm_out: &mut [u8]) -> Result<(), CryptoError> {
    if okm_out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    let hk = Hkdf::<sha2::Sha384>::from_prk(prk).map_err(|_| CryptoError::InvalidKey)?;
    hk.expand(info, okm_out)
        .map_err(|_| CryptoError::Internal("HKDF-SHA-384 expand failed (output too long)"))?;
    Ok(())
}

/// Perform HKDF-Extract with SHA-512, returning the pseudorandom key (PRK).
///
/// The PRK is always 64 bytes (the output size of SHA-512).
#[must_use]
pub fn hkdf_sha512_extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<sha2::Sha512>::extract(salt_opt, ikm);
    let mut out = [0u8; 64];
    out.copy_from_slice(&prk);
    out
}

/// Perform HKDF-Expand with SHA-512 from a pre-extracted PRK.
#[must_use = "HKDF expand result must be checked"]
pub fn hkdf_sha512_expand(prk: &[u8], info: &[u8], okm_out: &mut [u8]) -> Result<(), CryptoError> {
    if okm_out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    let hk = Hkdf::<sha2::Sha512>::from_prk(prk).map_err(|_| CryptoError::InvalidKey)?;
    hk.expand(info, okm_out)
        .map_err(|_| CryptoError::Internal("HKDF-SHA-512 expand failed (output too long)"))?;
    Ok(())
}

// ── HKDF derive-to-Vec convenience wrappers ───────────────────────────────────

/// Derive `len` bytes from `ikm`, `salt`, and `info` using HKDF-SHA-256, returning
/// the output as an owned `Vec<u8>`.
///
/// This is a convenience wrapper around [`HkdfSha256::derive`] (which performs
/// the full extract+expand sequence per RFC 5869).
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `len == 0` or if the requested output
/// exceeds 255 × 32 bytes (HKDF-SHA-256 maximum).
#[must_use = "HKDF derive result must be checked"]
pub fn hkdf_sha256_derive_to_vec(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if len == 0 {
        return Err(CryptoError::BadInput);
    }
    let mut out = vec![0u8; len];
    HkdfSha256.derive(ikm, salt, info, &mut out)?;
    Ok(out)
}

/// Derive `len` bytes from `ikm`, `salt`, and `info` using HKDF-SHA-384, returning
/// the output as an owned `Vec<u8>`.
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `len == 0` or if the requested output
/// exceeds 255 × 48 bytes (HKDF-SHA-384 maximum).
#[must_use = "HKDF derive result must be checked"]
pub fn hkdf_sha384_derive_to_vec(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if len == 0 {
        return Err(CryptoError::BadInput);
    }
    let mut out = vec![0u8; len];
    HkdfSha384.derive(ikm, salt, info, &mut out)?;
    Ok(out)
}

/// Derive `len` bytes from `ikm`, `salt`, and `info` using HKDF-SHA-512, returning
/// the output as an owned `Vec<u8>`.
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `len == 0` or if the requested output
/// exceeds 255 × 64 bytes (HKDF-SHA-512 maximum).
#[must_use = "HKDF derive result must be checked"]
pub fn hkdf_sha512_derive_to_vec(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if len == 0 {
        return Err(CryptoError::BadInput);
    }
    let mut out = vec![0u8; len];
    HkdfSha512.derive(ikm, salt, info, &mut out)?;
    Ok(out)
}

// ── Salt generation helpers ────────────────────────────────────────────────────

/// Generate a random 16-byte salt using the system CSPRNG.
///
/// Suitable for PBKDF2 (recommended ≥ 16 bytes per NIST SP 800-132) and
/// Argon2id (requires ≥ 8 bytes per RFC 9106).
///
/// # Errors
/// Returns [`CryptoError::Rng`] if the OS entropy source is unavailable.
#[must_use = "generated salt result must be checked"]
pub fn generate_salt_16() -> Result<[u8; 16], CryptoError> {
    let bytes = oxicrypto_rand::random_bytes(16)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Generate a random 32-byte salt using the system CSPRNG.
///
/// Suitable for Argon2id and scrypt where a longer salt provides additional
/// domain separation.
///
/// # Errors
/// Returns [`CryptoError::Rng`] if the OS entropy source is unavailable.
#[must_use = "generated salt result must be checked"]
pub fn generate_salt_32() -> Result<[u8; 32], CryptoError> {
    let bytes = oxicrypto_rand::random_bytes(32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// verify_password — constant-time password verification
// ---------------------------------------------------------------------------

/// Verify a password by re-hashing and comparing in constant time.
///
/// Hashes `password` with `salt` using `hasher` into a temporary buffer of
/// `expected.len()` bytes, then compares the result to `expected` using
/// [`subtle::ConstantTimeEq`].  The comparison time does not depend on the
/// position of the first differing byte.
///
/// # Errors
/// - Returns `Err(CryptoError::BadInput)` if `expected` is empty.
/// - Returns the underlying [`CryptoError`] if hashing fails (e.g. bad salt length).
/// - Returns `Err(CryptoError::InvalidTag)` if the password does not match.
///
/// # Example
/// ```ignore
/// use oxicrypto_kdf::{Argon2idHasher, Argon2Params, verify_password};
///
/// let hasher = Argon2idHasher::new(Argon2Params::TEST_PARAMS);
/// let salt   = b"0123456789abcdef";
/// let mut expected = [0u8; 32];
/// hasher.hash_password(b"password", salt, &hasher.params, &mut expected).unwrap();
///
/// verify_password(&hasher, b"password", salt, &expected).unwrap();        // ok
/// assert!(verify_password(&hasher, b"wrong", salt, &expected).is_err()); // rejected
/// ```
#[must_use = "password verification result must be checked"]
pub fn verify_password<H>(
    hasher: &H,
    password: &[u8],
    salt: &[u8],
    expected: &[u8],
) -> Result<(), CryptoError>
where
    H: PasswordHash,
{
    if expected.is_empty() {
        return Err(CryptoError::BadInput);
    }

    // Allocate a stack-sized temporary buffer.  For passwords the expected
    // output is typically 16–64 bytes, so heap allocation is not required;
    // but we use a Vec here to support arbitrary output lengths.
    let mut computed = vec![0u8; expected.len()];

    // Use empty params — each concrete hasher uses its own stored params.
    struct NullParams;
    impl oxicrypto_core::PasswordHashParams for NullParams {
        fn memory_cost(&self) -> Option<u32> {
            None
        }
        fn time_cost(&self) -> Option<u32> {
            None
        }
        fn parallelism(&self) -> Option<u32> {
            None
        }
    }

    hasher.hash_password(password, salt, &NullParams, &mut computed)?;

    // Constant-time comparison: returns 0x01 iff equal.
    let ok: bool = computed.ct_eq(expected).into();
    if ok {
        Ok(())
    } else {
        Err(CryptoError::InvalidTag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 5869 Test Case 1 for HKDF-SHA-256
    // Hash = SHA-256
    // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    // salt = 0x000102030405060708090a0b0c (13 bytes)
    // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
    // L    = 42 bytes
    // OKM  = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    #[test]
    fn hkdf_sha256_rfc5869_tc1() {
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let kdf = HkdfSha256;
        let mut okm = vec![0u8; 42];
        kdf.derive(&ikm, &salt, &info, &mut okm)
            .expect("HKDF-SHA-256 RFC5869 TC1 failed");
        assert_eq!(okm, expected, "HKDF-SHA-256 RFC5869 TC1 mismatch");
    }

    #[test]
    fn hkdf_sha256_empty_salt() {
        // Empty salt causes HKDF to use a zero-filled salt of hash length.
        let kdf = HkdfSha256;
        let mut okm = [0u8; 32];
        kdf.derive(b"input key material", b"", b"info", &mut okm)
            .expect("HKDF with empty salt failed");
        assert_ne!(okm, [0u8; 32]);
    }

    #[test]
    fn hkdf_sha512_round_trip() {
        let kdf = HkdfSha512;
        let mut okm1 = [0u8; 64];
        let mut okm2 = [0u8; 64];
        kdf.derive(b"secret", b"salt", b"info", &mut okm1).unwrap();
        kdf.derive(b"secret", b"salt", b"info", &mut okm2).unwrap();
        assert_eq!(okm1, okm2, "HKDF-SHA-512 must be deterministic");
        assert_ne!(okm1, [0u8; 64]);
    }

    #[test]
    fn hkdf_empty_output_errors() {
        let kdf = HkdfSha256;
        let result = kdf.derive(b"ikm", b"salt", b"info", &mut []);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    // ── HKDF-SHA-384 ─────────────────────────────────────────────────────────

    #[test]
    fn hkdf_sha384_round_trip() {
        let kdf = HkdfSha384;
        let mut okm1 = [0u8; 48];
        let mut okm2 = [0u8; 48];
        kdf.derive(b"secret", b"salt", b"info", &mut okm1)
            .expect("derive 1 failed");
        kdf.derive(b"secret", b"salt", b"info", &mut okm2)
            .expect("derive 2 failed");
        assert_eq!(okm1, okm2, "HKDF-SHA-384 must be deterministic");
        assert_ne!(okm1, [0u8; 48]);
    }

    #[test]
    fn hkdf_sha384_empty_output_errors() {
        let kdf = HkdfSha384;
        let result = kdf.derive(b"ikm", b"salt", b"info", &mut []);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    // ── Extract-only / Expand-only ───────────────────────────────────────────

    #[test]
    fn hkdf_sha256_extract_expand_equivalent() {
        // Extract+Expand should produce the same result as the full Kdf::derive.
        let ikm = b"input key material";
        let salt = b"salt value";
        let info = b"info";

        // Full derive.
        let kdf = HkdfSha256;
        let mut okm_full = [0u8; 42];
        kdf.derive(ikm, salt, info, &mut okm_full)
            .expect("full derive failed");

        // Separated extract + expand.
        let prk = hkdf_sha256_extract(salt, ikm);
        let mut okm_sep = [0u8; 42];
        hkdf_sha256_expand(&prk, info, &mut okm_sep).expect("expand failed");

        assert_eq!(okm_full, okm_sep, "Extract+Expand must equal full derive");
    }

    #[test]
    fn hkdf_sha384_extract_expand_round_trip() {
        let prk = hkdf_sha384_extract(b"salt", b"ikm");
        assert_eq!(prk.len(), 48);
        let mut okm = [0u8; 32];
        hkdf_sha384_expand(&prk, b"info", &mut okm).expect("expand failed");
        assert_ne!(okm, [0u8; 32]);
    }

    #[test]
    fn hkdf_sha512_extract_expand_round_trip() {
        let prk = hkdf_sha512_extract(b"salt", b"ikm");
        assert_eq!(prk.len(), 64);
        let mut okm = [0u8; 64];
        hkdf_sha512_expand(&prk, b"info", &mut okm).expect("expand failed");
        assert_ne!(okm, [0u8; 64]);
    }

    #[test]
    fn hkdf_expand_empty_output_errors() {
        let prk = hkdf_sha256_extract(b"salt", b"ikm");
        let result = hkdf_sha256_expand(&prk, b"info", &mut []);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    // ── verify_password ──────────────────────────────────────────────────────

    const VERIFY_SALT: &[u8] = b"0123456789abcdef"; // 16 bytes

    #[test]
    fn verify_password_argon2id_correct() {
        let hasher = Argon2idHasher::new(Argon2Params::TEST_PARAMS);
        let mut expected = [0u8; 32];
        hasher
            .hash_password(b"password", VERIFY_SALT, &hasher.params, &mut expected)
            .expect("hash");
        verify_password(&hasher, b"password", VERIFY_SALT, &expected)
            .expect("correct password must pass");
    }

    #[test]
    fn verify_password_argon2id_wrong_password() {
        let hasher = Argon2idHasher::new(Argon2Params::TEST_PARAMS);
        let mut expected = [0u8; 32];
        hasher
            .hash_password(b"password", VERIFY_SALT, &hasher.params, &mut expected)
            .expect("hash");
        let result = verify_password(&hasher, b"wrongpassword", VERIFY_SALT, &expected);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn verify_password_pbkdf2_correct() {
        let hasher = Pbkdf2Sha256Hasher::new(1_000);
        let mut expected = [0u8; 32];
        hasher
            .hash_password(b"mypassword", VERIFY_SALT, &hasher.params(), &mut expected)
            .expect("hash");
        verify_password(&hasher, b"mypassword", VERIFY_SALT, &expected)
            .expect("correct password must pass");
    }

    #[test]
    fn verify_password_pbkdf2_wrong_password() {
        let hasher = Pbkdf2Sha256Hasher::new(1_000);
        let mut expected = [0u8; 32];
        hasher
            .hash_password(b"mypassword", VERIFY_SALT, &hasher.params(), &mut expected)
            .expect("hash");
        let result = verify_password(&hasher, b"notmypassword", VERIFY_SALT, &expected);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn verify_password_empty_expected_errors() {
        let hasher = Pbkdf2Sha256Hasher::new(1_000);
        let result = verify_password(&hasher, b"password", VERIFY_SALT, &[]);
        assert_eq!(result, Err(CryptoError::BadInput));
    }
}
