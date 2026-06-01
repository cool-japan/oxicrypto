//! AES Key Wrap (RFC 3394 / NIST SP 800-38F).
//!
//! Wraps and unwraps key material using AES-128 or AES-256 as the block
//! cipher.  This module does **not** implement the [`Aead`](oxicrypto_core::Aead)
//! trait because key wrapping has no nonce and different semantics from AEAD.
//!
//! # Wire format
//!
//! Wrapped output is always `data.len() + 8` bytes (one RFC 3394 "semiblock"
//! of IV is prepended during wrapping and consumed during unwrapping).
//!
//! # Minimum input length
//!
//! RFC 3394 requires the plaintext to be at least two semiblocks (16 bytes)
//! and a multiple of 8 bytes.  These constraints are enforced here.

use aes_kw::{InnerInit, KeyInit, KwAes128, KwAes256};
use oxicrypto_core::CryptoError;

/// Minimum key-data length for AES-KW (two semiblocks = 16 bytes).
const MIN_DATA_LEN: usize = 16;

// ── AES-128-KW ───────────────────────────────────────────────────────────────

/// Wrap `data` with a 128-bit Key Encryption Key (KEK) using AES-128-KW.
///
/// # Arguments
///
/// * `kek`  — 16-byte Key Encryption Key.
/// * `data` — key material to wrap; must be ≥ 16 bytes and a multiple of 8.
/// * `out`  — output buffer; must be at least `data.len() + 8` bytes.
///
/// # Errors
///
/// * [`CryptoError::InvalidKey`] — `kek` is not 16 bytes.
/// * [`CryptoError::BadInput`]  — `data` violates length constraints.
/// * [`CryptoError::BufferTooSmall`] — `out` is too short.
pub fn aes128_key_wrap(kek: &[u8], data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    validate_data_len(data)?;
    let cipher = aes_kw::aes::Aes128::new_from_slice(kek).map_err(|_| CryptoError::InvalidKey)?;
    let kw = KwAes128::inner_init(cipher);
    kw.wrap_key(data, out).map_err(map_error)?;
    Ok(())
}

/// Unwrap `wrapped` with a 128-bit Key Encryption Key (KEK) using AES-128-KW.
///
/// # Arguments
///
/// * `kek`     — 16-byte Key Encryption Key.
/// * `wrapped` — wrapped key material; must be a multiple of 8 and ≥ 24 bytes.
/// * `out`     — output buffer; must be at least `wrapped.len() - 8` bytes.
///
/// # Errors
///
/// * [`CryptoError::InvalidKey`] — `kek` is not 16 bytes.
/// * [`CryptoError::BadInput`]   — `wrapped` violates length constraints.
/// * [`CryptoError::BufferTooSmall`] — `out` is too short.
/// * [`CryptoError::InvalidTag`] — integrity check failed (data tampered).
pub fn aes128_key_unwrap(kek: &[u8], wrapped: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    validate_wrapped_len(wrapped)?;
    let cipher = aes_kw::aes::Aes128::new_from_slice(kek).map_err(|_| CryptoError::InvalidKey)?;
    let kw = KwAes128::inner_init(cipher);
    kw.unwrap_key(wrapped, out).map_err(map_error)?;
    Ok(())
}

// ── AES-256-KW ───────────────────────────────────────────────────────────────

/// Wrap `data` with a 256-bit Key Encryption Key (KEK) using AES-256-KW.
///
/// # Arguments
///
/// * `kek`  — 32-byte Key Encryption Key.
/// * `data` — key material to wrap; must be ≥ 16 bytes and a multiple of 8.
/// * `out`  — output buffer; must be at least `data.len() + 8` bytes.
///
/// # Errors
///
/// * [`CryptoError::InvalidKey`] — `kek` is not 32 bytes.
/// * [`CryptoError::BadInput`]  — `data` violates length constraints.
/// * [`CryptoError::BufferTooSmall`] — `out` is too short.
pub fn aes256_key_wrap(kek: &[u8], data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    validate_data_len(data)?;
    let cipher = aes_kw::aes::Aes256::new_from_slice(kek).map_err(|_| CryptoError::InvalidKey)?;
    let kw = KwAes256::inner_init(cipher);
    kw.wrap_key(data, out).map_err(map_error)?;
    Ok(())
}

/// Unwrap `wrapped` with a 256-bit Key Encryption Key (KEK) using AES-256-KW.
///
/// # Arguments
///
/// * `kek`     — 32-byte Key Encryption Key.
/// * `wrapped` — wrapped key material; must be a multiple of 8 and ≥ 24 bytes.
/// * `out`     — output buffer; must be at least `wrapped.len() - 8` bytes.
///
/// # Errors
///
/// * [`CryptoError::InvalidKey`] — `kek` is not 32 bytes.
/// * [`CryptoError::BadInput`]   — `wrapped` violates length constraints.
/// * [`CryptoError::BufferTooSmall`] — `out` is too short.
/// * [`CryptoError::InvalidTag`] — integrity check failed (data tampered).
pub fn aes256_key_unwrap(kek: &[u8], wrapped: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    validate_wrapped_len(wrapped)?;
    let cipher = aes_kw::aes::Aes256::new_from_slice(kek).map_err(|_| CryptoError::InvalidKey)?;
    let kw = KwAes256::inner_init(cipher);
    kw.unwrap_key(wrapped, out).map_err(map_error)?;
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Validate plaintext data length: must be ≥ 16 bytes and a multiple of 8.
fn validate_data_len(data: &[u8]) -> Result<(), CryptoError> {
    if data.len() < MIN_DATA_LEN || !data.len().is_multiple_of(8) {
        return Err(CryptoError::BadInput);
    }
    Ok(())
}

/// Validate wrapped key length: must be a multiple of 8 and ≥ 24 bytes
/// (= MIN_DATA_LEN + IV_LEN).
fn validate_wrapped_len(wrapped: &[u8]) -> Result<(), CryptoError> {
    // MIN_DATA_LEN (16) + IV_LEN (8) = 24
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(CryptoError::BadInput);
    }
    Ok(())
}

/// Map `aes_kw::Error` to `CryptoError`.
fn map_error(e: aes_kw::Error) -> CryptoError {
    match e {
        aes_kw::Error::InvalidDataSize => CryptoError::BadInput,
        aes_kw::Error::InvalidOutputSize { .. } => CryptoError::BufferTooSmall,
        aes_kw::Error::IntegrityCheckFailed => CryptoError::InvalidTag,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 3394 §4.1 — 128-bit KEK, 128-bit key
    // KEK:     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
    // Key:     00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
    // Wrapped: 1F A6 8B 0A 81 12 B4 47 AE F3 4B D8 FB 5A 7B 82
    //          9D 3E 86 23 71 D2 CF E5
    const KEK_128: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    const KEY_128: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const WRAPPED_128: [u8; 24] = [
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B,
        0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    ];

    // RFC 3394 §4.6 — 256-bit KEK, 256-bit key
    // KEK: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
    //      10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
    // Key: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
    //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
    // Wrapped: 28 C9 F4 04 C4 B8 10 F4 CB CC B3 5C FB 87 F8 26
    //          3F 57 86 E2 D8 0E D3 26 CB C7 F0 E7 1A 99 F4 3B
    //          FB 98 8B 9B 7A 02 DD 21
    const KEK_256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    const KEY_256: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    ];
    const WRAPPED_256: [u8; 40] = [
        0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8,
        0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99,
        0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
    ];

    #[test]
    fn test_aes128_key_wrap_rfc3394_vec1() {
        let mut out = [0u8; 24];
        aes128_key_wrap(&KEK_128, &KEY_128, &mut out).expect("aes128_key_wrap failed");
        assert_eq!(
            out, WRAPPED_128,
            "AES-128-KW wrap mismatch against RFC 3394 §4.1"
        );
    }

    #[test]
    fn test_aes128_key_unwrap_rfc3394_vec1() {
        let mut out = [0u8; 16];
        aes128_key_unwrap(&KEK_128, &WRAPPED_128, &mut out).expect("aes128_key_unwrap failed");
        assert_eq!(
            out, KEY_128,
            "AES-128-KW unwrap mismatch against RFC 3394 §4.1"
        );
    }

    #[test]
    fn test_aes256_key_wrap_rfc3394() {
        let mut out = [0u8; 40];
        aes256_key_wrap(&KEK_256, &KEY_256, &mut out).expect("aes256_key_wrap failed");
        assert_eq!(
            out, WRAPPED_256,
            "AES-256-KW wrap mismatch against RFC 3394 §4.6"
        );
    }

    #[test]
    fn test_aes256_key_unwrap_rfc3394() {
        let mut out = [0u8; 32];
        aes256_key_unwrap(&KEK_256, &WRAPPED_256, &mut out).expect("aes256_key_unwrap failed");
        assert_eq!(
            out, KEY_256,
            "AES-256-KW unwrap mismatch against RFC 3394 §4.6"
        );
    }

    #[test]
    fn test_unwrap_tampered_fails() {
        let mut tampered = WRAPPED_128;
        tampered[0] ^= 0xFF; // flip a byte in the wrapped data
        let mut out = [0u8; 16];
        let result = aes128_key_unwrap(&KEK_128, &tampered, &mut out);
        assert_eq!(
            result,
            Err(CryptoError::InvalidTag),
            "tampered data must fail integrity check"
        );
    }

    #[test]
    fn test_invalid_data_length_rejected() {
        // 15 bytes: not a multiple of 8 and less than 16
        let short_data = [0u8; 15];
        let mut out = [0u8; 23];
        let result = aes128_key_wrap(&KEK_128, &short_data, &mut out);
        assert_eq!(
            result,
            Err(CryptoError::BadInput),
            "data < 16 bytes must be rejected"
        );
    }

    #[test]
    fn test_data_not_multiple_of_8_rejected() {
        // 17 bytes: not a multiple of 8
        let odd_data = [0u8; 17];
        let mut out = [0u8; 25];
        let result = aes128_key_wrap(&KEK_128, &odd_data, &mut out);
        assert_eq!(
            result,
            Err(CryptoError::BadInput),
            "data length not multiple of 8 must be rejected"
        );
    }

    #[test]
    fn test_wrong_kek_length_rejected() {
        let mut out = [0u8; 24];
        // Pass a 12-byte KEK instead of 16
        let result = aes128_key_wrap(&[0u8; 12], &KEY_128, &mut out);
        assert_eq!(
            result,
            Err(CryptoError::InvalidKey),
            "wrong KEK length must be rejected"
        );
    }

    #[test]
    fn test_output_buffer_too_small() {
        let mut out = [0u8; 20]; // needs 24 bytes
        let result = aes128_key_wrap(&KEK_128, &KEY_128, &mut out);
        assert_eq!(
            result,
            Err(CryptoError::BufferTooSmall),
            "short output buffer must fail"
        );
    }

    #[test]
    fn test_aes128_round_trip() {
        let key = [0xABu8; 32]; // 32-byte key material
        let mut wrapped = [0u8; 40];
        aes128_key_wrap(&KEK_128, &key, &mut wrapped).expect("wrap failed");
        let mut recovered = [0u8; 32];
        aes128_key_unwrap(&KEK_128, &wrapped, &mut recovered).expect("unwrap failed");
        assert_eq!(recovered, key, "round-trip must recover original key");
    }

    #[test]
    fn test_aes256_round_trip() {
        let key = [0xCDu8; 16];
        let mut wrapped = [0u8; 24];
        aes256_key_wrap(&KEK_256, &key, &mut wrapped).expect("wrap failed");
        let mut recovered = [0u8; 16];
        aes256_key_unwrap(&KEK_256, &wrapped, &mut recovered).expect("unwrap failed");
        assert_eq!(recovered, key, "round-trip must recover original key");
    }
}
