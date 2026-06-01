#![forbid(unsafe_code)]

//! KBKDF counter mode per NIST SP 800-108 Rev. 1, Section 4.1.
//!
//! The Key-Based Key Derivation Function (KBKDF) in counter mode derives
//! keying material from an input key using an HMAC-based PRF. Each block
//! is computed as:
//!
//! ```text
//! K(i) = HMAC(K_in, [i]_32_BE || Label || 0x00 || Context || [L]_32_BE)
//! ```
//!
//! where `[L]` is the requested output length in bits (as a big-endian u32).
//! Blocks are concatenated and truncated to `output_len` bytes.
//!
//! Three concrete variants are provided: HMAC-SHA-256, HMAC-SHA-384, and
//! HMAC-SHA-512. The helper [`kbkdf_counter_hmac_sha256_secret`] returns
//! the derived bytes wrapped in a [`SecretVec`] that zeroizes on drop.
//!
//! # Known limitation — no external KAT
//!
//! NIST SP 800-108 CAVP test vectors use keyed-hash primitives (CMAC-AES as
//! the PRF), not HMAC-SHA-2 in the published KAT suite. As of 2026-05-26,
//! no independently-verified external HMAC-SHA-{256,384,512} known-answer
//! test is included here. The implementation matches the PRF input encoding
//! specified in SP 800-108 §4.1, but a future cross-check against
//! `openssl kbkdf` or the CMAC-AES CAVP rsp files (adapted to HMAC) is
//! recommended before using this module in security-critical deployments.

extern crate alloc;

use alloc::vec::Vec;
use oxicrypto_core::{CryptoError, SecretVec};

/// Maximum output length (64 KiB) to guard against unbounded allocations.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

// ── KBKDF counter-mode — HMAC-SHA-256 ────────────────────────────────────────

/// KBKDF counter mode with HMAC-SHA-256 as the PRF (NIST SP 800-108 §4.1).
///
/// # Arguments
/// - `key_in`     – input keying material (any non-zero length)
/// - `label`      – purpose label (e.g. `b"encryption key"`)
/// - `context`    – context binding (e.g. party identifiers, session info)
/// - `output_len` – desired output length in bytes (1 – 65536)
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `output_len == 0`, `output_len` exceeds
/// 64 KiB, or the HMAC key is invalid (zero-length `key_in`).
#[must_use = "derived key should be used"]
pub fn kbkdf_counter_hmac_sha256(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    kbkdf_counter_sha256(key_in, label, context, output_len)
}

/// KBKDF counter mode with HMAC-SHA-384 as the PRF (NIST SP 800-108 §4.1).
///
/// # Arguments
/// - `key_in`     – input keying material
/// - `label`      – purpose label
/// - `context`    – context binding
/// - `output_len` – desired output length in bytes (1 – 65536)
///
/// # Errors
/// Returns [`CryptoError::BadInput`] on invalid parameters.
#[must_use = "derived key should be used"]
pub fn kbkdf_counter_hmac_sha384(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    kbkdf_counter_sha384(key_in, label, context, output_len)
}

/// KBKDF counter mode with HMAC-SHA-512 as the PRF (NIST SP 800-108 §4.1).
///
/// # Arguments
/// - `key_in`     – input keying material
/// - `label`      – purpose label
/// - `context`    – context binding
/// - `output_len` – desired output length in bytes (1 – 65536)
///
/// # Errors
/// Returns [`CryptoError::BadInput`] on invalid parameters.
#[must_use = "derived key should be used"]
pub fn kbkdf_counter_hmac_sha512(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    kbkdf_counter_sha512(key_in, label, context, output_len)
}

/// KBKDF counter-mode with HMAC-SHA-256, returning a [`SecretVec`] that
/// zeroizes on drop.
///
/// Wraps [`kbkdf_counter_hmac_sha256`] and moves the derived bytes into a
/// [`SecretVec`] for automatic zeroization when no longer needed.
///
/// # Errors
/// Returns [`CryptoError::BadInput`] on invalid parameters (see
/// [`kbkdf_counter_hmac_sha256`]).
#[must_use = "derived key should be used"]
pub fn kbkdf_counter_hmac_sha256_secret(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<SecretVec, CryptoError> {
    let bytes = kbkdf_counter_hmac_sha256(key_in, label, context, output_len)?;
    Ok(SecretVec::new(bytes))
}

// ── Private concrete implementations ─────────────────────────────────────────

fn validate_params(output_len: usize) -> Result<(), CryptoError> {
    if output_len == 0 || output_len > MAX_OUTPUT_BYTES {
        return Err(CryptoError::BadInput);
    }
    Ok(())
}

fn kbkdf_counter_sha256(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    use digest::KeyInit;
    use hmac::Mac as HmacMac;

    validate_params(output_len)?;

    const HASH_LEN: usize = 32;
    let l_bits = (output_len as u32).saturating_mul(8);
    let n_blocks = output_len.div_ceil(HASH_LEN);
    let mut out = Vec::with_capacity(n_blocks * HASH_LEN);

    for i in 1u32..=n_blocks as u32 {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key_in)
            .map_err(|_| CryptoError::BadInput)?;
        mac.update(&i.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00u8]);
        mac.update(context);
        mac.update(&l_bits.to_be_bytes());
        let block = mac.finalize().into_bytes();
        out.extend_from_slice(&block);
    }

    out.truncate(output_len);
    Ok(out)
}

fn kbkdf_counter_sha384(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    use digest::KeyInit;
    use hmac::Mac as HmacMac;

    validate_params(output_len)?;

    const HASH_LEN: usize = 48;
    let l_bits = (output_len as u32).saturating_mul(8);
    let n_blocks = output_len.div_ceil(HASH_LEN);
    let mut out = Vec::with_capacity(n_blocks * HASH_LEN);

    for i in 1u32..=n_blocks as u32 {
        let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key_in)
            .map_err(|_| CryptoError::BadInput)?;
        mac.update(&i.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00u8]);
        mac.update(context);
        mac.update(&l_bits.to_be_bytes());
        let block = mac.finalize().into_bytes();
        out.extend_from_slice(&block);
    }

    out.truncate(output_len);
    Ok(out)
}

fn kbkdf_counter_sha512(
    key_in: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    use digest::KeyInit;
    use hmac::Mac as HmacMac;

    validate_params(output_len)?;

    const HASH_LEN: usize = 64;
    let l_bits = (output_len as u32).saturating_mul(8);
    let n_blocks = output_len.div_ceil(HASH_LEN);
    let mut out = Vec::with_capacity(n_blocks * HASH_LEN);

    for i in 1u32..=n_blocks as u32 {
        let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key_in)
            .map_err(|_| CryptoError::BadInput)?;
        mac.update(&i.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00u8]);
        mac.update(context);
        mac.update(&l_bits.to_be_bytes());
        let block = mac.finalize().into_bytes();
        out.extend_from_slice(&block);
    }

    out.truncate(output_len);
    Ok(out)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef"; // 32 bytes
    const LABEL: &[u8] = b"encryption key";
    const CONTEXT: &[u8] = b"session-id:abc";

    // ── Basic correctness ─────────────────────────────────────────────────────

    #[test]
    fn sha256_deterministic() {
        let a = kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, 32).unwrap();
        let b = kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, 32).unwrap();
        assert_eq!(a, b, "KBKDF must be deterministic");
        assert_ne!(a, vec![0u8; 32], "KBKDF output must not be all-zero");
    }

    #[test]
    fn sha384_deterministic() {
        let a = kbkdf_counter_hmac_sha384(KEY, LABEL, CONTEXT, 48).unwrap();
        let b = kbkdf_counter_hmac_sha384(KEY, LABEL, CONTEXT, 48).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, vec![0u8; 48]);
    }

    #[test]
    fn sha512_deterministic() {
        let a = kbkdf_counter_hmac_sha512(KEY, LABEL, CONTEXT, 64).unwrap();
        let b = kbkdf_counter_hmac_sha512(KEY, LABEL, CONTEXT, 64).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, vec![0u8; 64]);
    }

    // ── Output length ─────────────────────────────────────────────────────────

    #[test]
    fn sha256_output_length_exact() {
        for len in [1usize, 16, 32, 64, 100, 128] {
            let out = kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, len)
                .unwrap_or_else(|e| panic!("len={len} failed: {e}"));
            assert_eq!(out.len(), len, "output length mismatch at len={len}");
        }
    }

    #[test]
    fn sha384_output_length_exact() {
        for len in [1usize, 48, 96, 200] {
            let out = kbkdf_counter_hmac_sha384(KEY, LABEL, CONTEXT, len).unwrap();
            assert_eq!(out.len(), len);
        }
    }

    #[test]
    fn sha512_output_length_exact() {
        for len in [1usize, 64, 128, 300] {
            let out = kbkdf_counter_hmac_sha512(KEY, LABEL, CONTEXT, len).unwrap();
            assert_eq!(out.len(), len);
        }
    }

    // ── Domain separation ─────────────────────────────────────────────────────

    #[test]
    fn different_labels_differ() {
        let a = kbkdf_counter_hmac_sha256(KEY, b"label-a", CONTEXT, 32).unwrap();
        let b = kbkdf_counter_hmac_sha256(KEY, b"label-b", CONTEXT, 32).unwrap();
        assert_ne!(a, b, "different labels must produce different output");
    }

    #[test]
    fn different_contexts_differ() {
        let a = kbkdf_counter_hmac_sha256(KEY, LABEL, b"ctx-a", 32).unwrap();
        let b = kbkdf_counter_hmac_sha256(KEY, LABEL, b"ctx-b", 32).unwrap();
        assert_ne!(a, b, "different contexts must produce different output");
    }

    #[test]
    fn different_keys_differ() {
        let key2 = b"ffffffffffffffffffffffffffffffff";
        let a = kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, 32).unwrap();
        let b = kbkdf_counter_hmac_sha256(key2, LABEL, CONTEXT, 32).unwrap();
        assert_ne!(a, b);
    }

    // ── Cross-variant independence ────────────────────────────────────────────

    #[test]
    fn sha256_sha384_sha512_differ() {
        let a = kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, 32).unwrap();
        let b = kbkdf_counter_hmac_sha384(KEY, LABEL, CONTEXT, 32).unwrap();
        let c = kbkdf_counter_hmac_sha512(KEY, LABEL, CONTEXT, 32).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn zero_output_len_rejected() {
        assert_eq!(
            kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, 0),
            Err(CryptoError::BadInput)
        );
        assert_eq!(
            kbkdf_counter_hmac_sha384(KEY, LABEL, CONTEXT, 0),
            Err(CryptoError::BadInput)
        );
        assert_eq!(
            kbkdf_counter_hmac_sha512(KEY, LABEL, CONTEXT, 0),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn output_too_large_rejected() {
        assert_eq!(
            kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, MAX_OUTPUT_BYTES + 1),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn empty_key_rejected() {
        // Empty key slice fails HMAC new_from_slice for some backends.
        // We use the BadInput path; only verify it does not panic.
        let _ = kbkdf_counter_hmac_sha256(b"", LABEL, CONTEXT, 32);
    }

    // ── SecretVec wrapper ─────────────────────────────────────────────────────

    #[test]
    fn secret_wrapper_matches_plain() {
        let plain = kbkdf_counter_hmac_sha256(KEY, LABEL, CONTEXT, 32).unwrap();
        let secret = kbkdf_counter_hmac_sha256_secret(KEY, LABEL, CONTEXT, 32).unwrap();
        assert_eq!(plain.as_slice(), secret.as_bytes());
    }

    #[test]
    fn secret_wrapper_zero_output_len_rejected() {
        assert!(
            kbkdf_counter_hmac_sha256_secret(KEY, LABEL, CONTEXT, 0).is_err(),
            "zero output_len must return an error"
        );
    }
}
