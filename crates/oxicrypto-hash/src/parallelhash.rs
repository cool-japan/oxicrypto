// ── ParallelHash128 / ParallelHash256 (NIST SP 800-185 §6) ──────────────────
//
//! ParallelHash128 and ParallelHash256, the SHA-3 derived parallelisable hash
//! functions defined in NIST SP 800-185 §6.
//!
//! ParallelHash is designed so that long messages can be hashed by processing
//! fixed-size blocks independently. This module implements the construction
//! **sequentially** (pure Rust, no threading dependency); the per-block chaining
//! values are independent, so a future `parallel` feature could compute them on
//! multiple threads while producing byte-identical output.
//!
//! # Construction (SP 800-185 §6.1 / §6.2)
//!
//! Given message `X`, block size `B` (bytes), customization `S`, and output
//! length `L` (bits), split `X` into `n = ceil(len(X) / B)` blocks
//! `X_0 ‖ X_1 ‖ … ‖ X_{n-1}` (the final block may be shorter than `B`). Then:
//!
//! ```text
//! z = left_encode(B)
//!   ‖ SHAKE128(X_0, 256) ‖ … ‖ SHAKE128(X_{n-1}, 256)   (256-bit CVs for 128)
//!   ‖ right_encode(n)
//!   ‖ right_encode(L)
//! ParallelHash128(X, B, L, S) = cSHAKE128(z, L, "ParallelHash", S)
//! ```
//!
//! ParallelHash256 is identical with SHAKE256 producing 512-bit (64-byte)
//! chaining values and cSHAKE256 as the final compression. The XOF variants set
//! `L = 0` in `right_encode(L)` and stream arbitrary-length output.
//!
//! The per-block hash is `cSHAKE128(X_i, 256, "", "")`, which (with empty
//! function-name and empty customization) equals `SHAKE128(X_i, 256)`; this
//! implementation uses [`crate::shake128`] / [`crate::shake256`] directly for
//! those chaining values.
//!
//! # Examples
//!
//! ```
//! use oxicrypto_hash::parallel_hash128;
//!
//! // NIST SP 800-185 ParallelHash128 Sample #1: B = 8, S = "", L = 256.
//! let data: [u8; 24] = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
//!     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
//! ];
//! let mut out = [0u8; 32];
//! parallel_hash128(&data, 8, b"", &mut out).unwrap();
//! assert_eq!(
//!     out,
//!     [
//!         0xBA, 0x8D, 0xC1, 0xD1, 0xD9, 0x79, 0x33, 0x1D,
//!         0x3F, 0x81, 0x36, 0x03, 0xC6, 0x7F, 0x72, 0x60,
//!         0x9A, 0xB5, 0xE4, 0x4B, 0x94, 0xA0, 0xB8, 0xF9,
//!         0xAF, 0x46, 0x51, 0x44, 0x54, 0xA2, 0xB4, 0xF5,
//!     ]
//! );
//! ```

use alloc::vec::Vec;

use oxicrypto_core::CryptoError;

use crate::xof::{left_encode, right_encode};
use crate::{cshake128, cshake256, shake128, shake256};

/// Function-name string `N` used by every ParallelHash variant (SP 800-185 §6).
const PARALLEL_HASH_NAME: &[u8] = b"ParallelHash";

/// Chaining-value length for ParallelHash128 (256 bits = 32 bytes).
const CV_LEN_128: usize = 32;

/// Chaining-value length for ParallelHash256 (512 bits = 64 bytes).
const CV_LEN_256: usize = 64;

/// Build the `z` preimage (the cSHAKE input) shared by all ParallelHash variants.
///
/// `cv_len` selects the per-block chaining-value width (32 for the 128-bit
/// strength, 64 for the 256-bit strength). `out_bits` is the encoded output
/// length `L`: a positive value for the fixed-output variants, or `0` for the
/// XOF variants per SP 800-185.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `block_size` is `0`, or if a length
/// computation overflows a `u64` (unreachable in practice).
fn parallel_hash_z(
    data: &[u8],
    block_size: usize,
    out_bits: u64,
    cv_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if block_size == 0 {
        return Err(CryptoError::BadInput);
    }

    // n = ceil(len(data) / block_size). For empty data, n = 0 (SP 800-185).
    let n_blocks = data.len() / block_size + usize::from(!data.len().is_multiple_of(block_size));

    // `left_encode(B)` encodes the block size in *bytes* (SP 800-185 §6), unlike
    // `encode_string`, which encodes a bit length.
    let mut z = left_encode(block_size as u64);

    // Each block contributes a chaining value CV_i of `cv_len` bytes.
    let mut cv = alloc::vec![0u8; cv_len];
    for block in data.chunks(block_size) {
        match cv_len {
            CV_LEN_128 => shake128(block, &mut cv),
            CV_LEN_256 => shake256(block, &mut cv),
            // Unreachable: only the two constants above are ever passed in.
            _ => return Err(CryptoError::Internal("invalid ParallelHash CV length")),
        }
        z.extend_from_slice(&cv);
    }

    z.extend_from_slice(&right_encode(n_blocks as u64));
    z.extend_from_slice(&right_encode(out_bits));
    Ok(z)
}

/// Compute the encoded output-length value `right_encode(out.len() * 8)`.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `out.len() * 8` overflows a `u64`.
fn out_len_bits(out: &[u8]) -> Result<u64, CryptoError> {
    (out.len() as u64)
        .checked_mul(8)
        .ok_or(CryptoError::BadInput)
}

// ── ParallelHash128 (fixed output) ──────────────────────────────────────────

/// ParallelHash128 with fixed output length (NIST SP 800-185 §6.1).
///
/// Hashes `data` in `block_size`-byte blocks with optional `customization`
/// string `S`; the output length is `out.len()` bytes.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `block_size` is `0` or a length
/// computation overflows (unreachable in practice).
pub fn parallel_hash128(
    data: &[u8],
    block_size: usize,
    customization: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let out_bits = out_len_bits(out)?;
    let z = parallel_hash_z(data, block_size, out_bits, CV_LEN_128)?;
    cshake128(&z, PARALLEL_HASH_NAME, customization, out);
    Ok(())
}

/// ParallelHash256 with fixed output length (NIST SP 800-185 §6.2).
///
/// Hashes `data` in `block_size`-byte blocks with optional `customization`
/// string `S`; the output length is `out.len()` bytes.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `block_size` is `0` or a length
/// computation overflows (unreachable in practice).
pub fn parallel_hash256(
    data: &[u8],
    block_size: usize,
    customization: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let out_bits = out_len_bits(out)?;
    let z = parallel_hash_z(data, block_size, out_bits, CV_LEN_256)?;
    cshake256(&z, PARALLEL_HASH_NAME, customization, out);
    Ok(())
}

// ── ParallelHashXOF variants ────────────────────────────────────────────────

/// ParallelHash128 in extendable-output (XOF) mode (NIST SP 800-185 §6.3).
///
/// Identical to [`parallel_hash128`] except the encoded output length is `0`
/// (`right_encode(0)`), making the output an arbitrary-length stream rather than
/// being domain-separated by a fixed length. `out.len()` bytes are produced.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `block_size` is `0`.
pub fn parallel_hash128_xof(
    data: &[u8],
    block_size: usize,
    customization: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let z = parallel_hash_z(data, block_size, 0, CV_LEN_128)?;
    cshake128(&z, PARALLEL_HASH_NAME, customization, out);
    Ok(())
}

/// ParallelHash256 in extendable-output (XOF) mode (NIST SP 800-185 §6.3).
///
/// Identical to [`parallel_hash256`] except the encoded output length is `0`.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `block_size` is `0`.
pub fn parallel_hash256_xof(
    data: &[u8],
    block_size: usize,
    customization: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let z = parallel_hash_z(data, block_size, 0, CV_LEN_256)?;
    cshake256(&z, PARALLEL_HASH_NAME, customization, out);
    Ok(())
}

// ── Convenience struct wrappers ─────────────────────────────────────────────

/// ParallelHash128 configured with a block size and customization string.
///
/// A small convenience wrapper over [`parallel_hash128`] /
/// [`parallel_hash128_xof`] holding the parameters that stay fixed across calls.
#[derive(Debug, Clone)]
pub struct ParallelHash128 {
    block_size: usize,
    customization: Vec<u8>,
}

impl ParallelHash128 {
    /// Create a ParallelHash128 with the given `block_size` (bytes) and
    /// `customization` string `S`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BadInput`] if `block_size` is `0`.
    pub fn new(block_size: usize, customization: &[u8]) -> Result<Self, CryptoError> {
        if block_size == 0 {
            return Err(CryptoError::BadInput);
        }
        Ok(Self {
            block_size,
            customization: customization.to_vec(),
        })
    }

    /// Hash `data` with fixed output length `out.len()` bytes.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`parallel_hash128`].
    pub fn hash(&self, data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        parallel_hash128(data, self.block_size, &self.customization, out)
    }

    /// Hash `data` in XOF mode, producing `out.len()` bytes.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`parallel_hash128_xof`].
    pub fn hash_xof(&self, data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        parallel_hash128_xof(data, self.block_size, &self.customization, out)
    }
}

/// ParallelHash256 configured with a block size and customization string.
///
/// A small convenience wrapper over [`parallel_hash256`] /
/// [`parallel_hash256_xof`].
#[derive(Debug, Clone)]
pub struct ParallelHash256 {
    block_size: usize,
    customization: Vec<u8>,
}

impl ParallelHash256 {
    /// Create a ParallelHash256 with the given `block_size` (bytes) and
    /// `customization` string `S`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BadInput`] if `block_size` is `0`.
    pub fn new(block_size: usize, customization: &[u8]) -> Result<Self, CryptoError> {
        if block_size == 0 {
            return Err(CryptoError::BadInput);
        }
        Ok(Self {
            block_size,
            customization: customization.to_vec(),
        })
    }

    /// Hash `data` with fixed output length `out.len()` bytes.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`parallel_hash256`].
    pub fn hash(&self, data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        parallel_hash256(data, self.block_size, &self.customization, out)
    }

    /// Hash `data` in XOF mode, producing `out.len()` bytes.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`parallel_hash256_xof`].
    pub fn hash_xof(&self, data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        parallel_hash256_xof(data, self.block_size, &self.customization, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_hash128_block_size_zero_rejected() {
        let mut out = [0u8; 32];
        assert_eq!(
            parallel_hash128(b"data", 0, b"", &mut out).unwrap_err(),
            CryptoError::BadInput
        );
    }

    #[test]
    fn parallel_hash256_block_size_zero_rejected() {
        let mut out = [0u8; 64];
        assert_eq!(
            parallel_hash256(b"data", 0, b"", &mut out).unwrap_err(),
            CryptoError::BadInput
        );
    }

    #[test]
    fn struct_new_block_size_zero_rejected() {
        assert_eq!(
            ParallelHash128::new(0, b"").unwrap_err(),
            CryptoError::BadInput
        );
        assert_eq!(
            ParallelHash256::new(0, b"").unwrap_err(),
            CryptoError::BadInput
        );
    }

    #[test]
    fn struct_matches_free_function_128() {
        let data = b"some parallel hash payload spanning multiple blocks";
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        parallel_hash128(data, 8, b"cust", &mut a).unwrap();
        ParallelHash128::new(8, b"cust")
            .unwrap()
            .hash(data, &mut b)
            .unwrap();
        assert_eq!(a, b, "struct API must equal free function (PH128)");
    }

    #[test]
    fn struct_matches_free_function_256() {
        let data = b"some parallel hash payload spanning multiple blocks";
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        parallel_hash256(data, 16, b"cust", &mut a).unwrap();
        ParallelHash256::new(16, b"cust")
            .unwrap()
            .hash(data, &mut b)
            .unwrap();
        assert_eq!(a, b, "struct API must equal free function (PH256)");
    }

    #[test]
    fn customization_changes_output_128() {
        let data = b"abcdefghijklmnop";
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        parallel_hash128(data, 8, b"A", &mut a).unwrap();
        parallel_hash128(data, 8, b"B", &mut b).unwrap();
        assert_ne!(a, b, "different customization must change PH128 output");
    }

    #[test]
    fn block_size_changes_output_128() {
        // ParallelHash output depends on the block size (different CV layout).
        let data = b"abcdefghijklmnopqrstuvwx";
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        parallel_hash128(data, 8, b"", &mut a).unwrap();
        parallel_hash128(data, 12, b"", &mut b).unwrap();
        assert_ne!(a, b, "different block size must change PH128 output");
    }

    #[test]
    fn xof_prefix_consistency_128() {
        // A longer XOF output must extend a shorter one (same parameters).
        let data = b"xof prefix consistency check payload";
        let mut short = [0u8; 32];
        let mut long = [0u8; 80];
        parallel_hash128_xof(data, 8, b"cust", &mut short).unwrap();
        parallel_hash128_xof(data, 8, b"cust", &mut long).unwrap();
        assert_eq!(
            short,
            long[..32],
            "PH128 XOF: short output must prefix the longer one"
        );
    }

    #[test]
    fn xof_prefix_consistency_256() {
        let data = b"xof prefix consistency check payload";
        let mut short = [0u8; 64];
        let mut long = [0u8; 160];
        parallel_hash256_xof(data, 16, b"cust", &mut short).unwrap();
        parallel_hash256_xof(data, 16, b"cust", &mut long).unwrap();
        assert_eq!(
            short,
            long[..64],
            "PH256 XOF: short output must prefix the longer one"
        );
    }

    #[test]
    fn xof_differs_from_fixed_128() {
        // The fixed-output and XOF variants differ (right_encode(L) vs right_encode(0)).
        let data = b"some data here";
        let mut fixed = [0u8; 32];
        let mut xof = [0u8; 32];
        parallel_hash128(data, 8, b"", &mut fixed).unwrap();
        parallel_hash128_xof(data, 8, b"", &mut xof).unwrap();
        assert_ne!(fixed, xof, "fixed-output and XOF variants must differ");
    }

    #[test]
    fn empty_input_is_defined_128() {
        // n = 0 for empty input: z = left_encode(B) ‖ right_encode(0) ‖ right_encode(L).
        let mut out = [0u8; 32];
        parallel_hash128(b"", 8, b"", &mut out).unwrap();
        assert!(
            out.iter().any(|&x| x != 0),
            "PH128 of empty input must be non-zero"
        );
    }

    #[test]
    fn partial_final_block_is_handled_128() {
        // 20 bytes with B = 8 => blocks of 8, 8, 4 (last is partial).
        let data: [u8; 20] = core::array::from_fn(|i| i as u8);
        let mut out = [0u8; 32];
        // Must not panic and must be deterministic.
        parallel_hash128(&data, 8, b"", &mut out).unwrap();
        let mut out2 = [0u8; 32];
        parallel_hash128(&data, 8, b"", &mut out2).unwrap();
        assert_eq!(out, out2, "PH128 with partial final block must be stable");
    }
}
