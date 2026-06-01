// ── XOF / cSHAKE / TupleHash / BLAKE2b-keyed / hash_file ────────────────────
//
//! Extendable-output functions (XOFs) and related constructs per NIST SP 800-185.
//!
//! Provides:
//! - SHAKE128 / SHAKE256 XOFs (FIPS 202)
//! - cSHAKE128 / cSHAKE256 with function-name and customization strings
//! - TupleHash128 / TupleHash256 (unambiguous encoding of byte-string tuples)
//! - BLAKE2b keyed-hash (variable-length MAC mode, RFC 7693)
//! - [`hash_file`] convenience functions (behind `std` feature)

use alloc::vec::Vec;
use cshake::digest::{ExtendableOutput, Update, XofReader};
use oxicrypto_core::CryptoError;
use shake::digest::{ExtendableOutput as ShakeExtend, Update as ShakeUpdate};

// ── SHAKE128 / SHAKE256 ───────────────────────────────────────────────────────

/// SHAKE128 XOF reader: stream an arbitrary number of output bytes from a
/// finalised SHAKE128 state.
pub struct Shake128Reader(shake::Shake128Reader);

impl Shake128Reader {
    /// Fill `out` with the next output bytes.
    pub fn read(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// SHAKE256 XOF reader: stream an arbitrary number of output bytes from a
/// finalised SHAKE256 state.
pub struct Shake256Reader(shake::Shake256Reader);

impl Shake256Reader {
    /// Fill `out` with the next output bytes.
    pub fn read(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// Hash `msg` with SHAKE128 and fill `out` with extendable output.
pub fn shake128(msg: &[u8], out: &mut [u8]) {
    let mut h = shake::Shake128::default();
    ShakeUpdate::update(&mut h, msg);
    let mut reader = ShakeExtend::finalize_xof(h);
    reader.read(out);
}

/// Hash `msg` with SHAKE256 and fill `out` with extendable output.
pub fn shake256(msg: &[u8], out: &mut [u8]) {
    let mut h = shake::Shake256::default();
    ShakeUpdate::update(&mut h, msg);
    let mut reader = ShakeExtend::finalize_xof(h);
    reader.read(out);
}

/// Begin a SHAKE128 computation, returning a finalisable hasher.
///
/// The `msg` argument absorbs message data; the returned [`Shake128Reader`]
/// provides streaming output.
pub fn shake128_start(msg: &[u8]) -> Shake128Reader {
    let mut h = shake::Shake128::default();
    ShakeUpdate::update(&mut h, msg);
    Shake128Reader(ShakeExtend::finalize_xof(h))
}

/// Begin a SHAKE256 computation, returning a finalisable hasher.
pub fn shake256_start(msg: &[u8]) -> Shake256Reader {
    let mut h = shake::Shake256::default();
    ShakeUpdate::update(&mut h, msg);
    Shake256Reader(ShakeExtend::finalize_xof(h))
}

// ── cSHAKE128 / cSHAKE256 ────────────────────────────────────────────────────

/// Hash `msg` with cSHAKE128 (NIST SP 800-185 §3) and fill `out`.
///
/// When both `function_name` and `customization` are empty this degrades to
/// SHAKE128 (per spec).
pub fn cshake128(msg: &[u8], function_name: &[u8], customization: &[u8], out: &mut [u8]) {
    let mut h = cshake::CShake128::new_with_function_name(function_name, customization);
    Update::update(&mut h, msg);
    let mut reader = ExtendableOutput::finalize_xof(h);
    reader.read(out);
}

/// Hash `msg` with cSHAKE256 (NIST SP 800-185 §3) and fill `out`.
///
/// When both `function_name` and `customization` are empty this degrades to
/// SHAKE256 (per spec).
pub fn cshake256(msg: &[u8], function_name: &[u8], customization: &[u8], out: &mut [u8]) {
    let mut h = cshake::CShake256::new_with_function_name(function_name, customization);
    Update::update(&mut h, msg);
    let mut reader = ExtendableOutput::finalize_xof(h);
    reader.read(out);
}

// ── TupleHash encoding helpers (SP 800-185 §2.3) ────────────────────────────

/// `left_encode(x)`: big-endian byte encoding of `x`, prepended by a 1-byte
/// length count indicating the number of non-zero bytes.
pub(crate) fn left_encode(x: u64) -> Vec<u8> {
    if x == 0 {
        return alloc::vec![1u8, 0u8];
    }
    let be = x.to_be_bytes();
    let leading_zeros = be.iter().take_while(|&&b| b == 0).count();
    let n = 8 - leading_zeros; // number of significant bytes
    let mut out = Vec::with_capacity(1 + n);
    out.push(n as u8);
    out.extend_from_slice(&be[leading_zeros..]);
    out
}

/// `right_encode(x)`: big-endian byte encoding of `x`, followed by a 1-byte
/// length count indicating the number of non-zero bytes.
pub(crate) fn right_encode(x: u64) -> Vec<u8> {
    if x == 0 {
        return alloc::vec![0u8, 1u8];
    }
    let be = x.to_be_bytes();
    let leading_zeros = be.iter().take_while(|&&b| b == 0).count();
    let n = 8 - leading_zeros;
    let mut out = Vec::with_capacity(n + 1);
    out.extend_from_slice(&be[leading_zeros..]);
    out.push(n as u8);
    out
}

/// `encode_string(s)` = `left_encode(s.len() * 8)` || `s`.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `s.len() * 8` overflows a `u64`. This is
/// unreachable in practice (a slice cannot exceed `isize::MAX` bytes), but the
/// check avoids any panic per the no-unwrap policy.
pub(crate) fn encode_string(s: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let bit_len = (s.len() as u64)
        .checked_mul(8)
        .ok_or(CryptoError::BadInput)?;
    let mut out = left_encode(bit_len);
    out.extend_from_slice(s);
    Ok(out)
}

// ── TupleHash128 / TupleHash256 ───────────────────────────────────────────────

/// TupleHash128 (NIST SP 800-185 §5).
///
/// Hashes the *tuple* of byte strings in `inputs` with optional `customization`
/// string; result length equals `out.len()`.
///
/// Crucially, `tuple_hash128(&[b"ab", b"c"], ...)` differs from
/// `tuple_hash128(&[b"a", b"bc"], ...)` — the encoding is unambiguous.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if any input length or `out.len()`,
/// multiplied by 8, overflows a `u64` (unreachable in practice).
pub fn tuple_hash128(
    inputs: &[&[u8]],
    customization: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut h = cshake::CShake128::new_with_function_name(b"TupleHash", customization);

    // encode_tuple(X) = encode_string(X[0]) || ... || encode_string(X[n-1])
    for &input in inputs {
        let encoded = encode_string(input)?;
        Update::update(&mut h, &encoded);
    }

    // right_encode(L) where L = output length in bits
    let out_bits = (out.len() as u64)
        .checked_mul(8)
        .ok_or(CryptoError::BadInput)?;
    let renc = right_encode(out_bits);
    Update::update(&mut h, &renc);

    let mut reader = ExtendableOutput::finalize_xof(h);
    reader.read(out);
    Ok(())
}

/// TupleHash256 (NIST SP 800-185 §5).
///
/// Hashes the *tuple* of byte strings in `inputs` with optional `customization`
/// string; result length equals `out.len()`.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if any input length or `out.len()`,
/// multiplied by 8, overflows a `u64` (unreachable in practice).
pub fn tuple_hash256(
    inputs: &[&[u8]],
    customization: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut h = cshake::CShake256::new_with_function_name(b"TupleHash", customization);

    for &input in inputs {
        let encoded = encode_string(input)?;
        Update::update(&mut h, &encoded);
    }

    let out_bits = (out.len() as u64)
        .checked_mul(8)
        .ok_or(CryptoError::BadInput)?;
    let renc = right_encode(out_bits);
    Update::update(&mut h, &renc);

    let mut reader = ExtendableOutput::finalize_xof(h);
    reader.read(out);
    Ok(())
}

// ── BLAKE2b keyed-hash mode ───────────────────────────────────────────────────

/// BLAKE2b keyed-hash (MAC mode), with variable output size 1–64 bytes.
///
/// BLAKE2b in keyed mode is a one-pass MAC: the key is absorbed as the first
/// block. Keys must be between 1 and 64 bytes inclusive.
pub struct Blake2bKeyed {
    key: Vec<u8>,
}

impl core::fmt::Debug for Blake2bKeyed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Blake2bKeyed(***)")
    }
}

impl Blake2bKeyed {
    /// Create a keyed BLAKE2b hasher.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if `key` is empty or longer than 64 bytes.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.is_empty() || key.len() > 64 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Hash `msg` under this key; output is written to `out`.
    ///
    /// `out.len()` must be between 1 and 64 bytes inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BadInput`] if `out` is empty or longer than 64 bytes.
    /// Returns [`CryptoError::InvalidKey`] if the key is invalid (should not
    /// happen after successful [`new`](Self::new)).
    pub fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        blake2b_keyed(&self.key, msg, out)
    }
}

/// Hash `msg` under `key` with BLAKE2b in keyed mode; output is written to `out`.
///
/// Both `key.len()` (1–64 bytes) and `out.len()` (1–64 bytes) are validated.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if `key` is empty or longer than 64 bytes.
/// Returns [`CryptoError::BadInput`] if `out` is empty or longer than 64 bytes.
pub fn blake2b_keyed(key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    use blake2::digest::{FixedOutput, KeyInit, Update as MacUpdate};

    if key.is_empty() || key.len() > 64 {
        return Err(CryptoError::InvalidKey);
    }
    if out.is_empty() || out.len() > 64 {
        return Err(CryptoError::BadInput);
    }

    // Blake2bMac512 gives a full 64-byte MAC; we then truncate to out.len()
    let mut mac =
        blake2::Blake2bMac512::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    MacUpdate::update(&mut mac, msg);
    let full = mac.finalize_fixed();
    out.copy_from_slice(&full[..out.len()]);
    Ok(())
}

// ── hash_file (std feature) ───────────────────────────────────────────────────

/// Hash a file at `path` with SHA-256, returning a 32-byte digest.
///
/// Reads the file in 64 KB chunks. Maps I/O errors to [`CryptoError::Internal`].
///
/// # Errors
///
/// Returns [`CryptoError::Internal`] if the file cannot be read.
#[cfg(feature = "std")]
pub fn hash_file_sha256(path: &std::path::Path) -> Result<[u8; 32], CryptoError> {
    use sha2::Digest;
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|_| CryptoError::Internal("cannot open file"))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut buf = alloc::vec![0u8; 65536];

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| CryptoError::Internal("file read error"))?;
        if n == 0 {
            break;
        }
        Digest::update(&mut hasher, &buf[..n]);
    }

    let result = Digest::finalize(hasher);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Hash a file at `path` with SHA-512, returning a 64-byte digest.
///
/// Reads the file in 64 KB chunks. Maps I/O errors to [`CryptoError::Internal`].
///
/// # Errors
///
/// Returns [`CryptoError::Internal`] if the file cannot be read.
#[cfg(feature = "std")]
pub fn hash_file_sha512(path: &std::path::Path) -> Result<[u8; 64], CryptoError> {
    use sha2::Digest;
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|_| CryptoError::Internal("cannot open file"))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = sha2::Sha512::new();
    let mut buf = alloc::vec![0u8; 65536];

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| CryptoError::Internal("file read error"))?;
        if n == 0 {
            break;
        }
        Digest::update(&mut hasher, &buf[..n]);
    }

    let result = Digest::finalize(hasher);
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Hash a file at `path` with BLAKE3, returning a 32-byte digest.
///
/// Reads the file in 64 KB chunks. Maps I/O errors to [`CryptoError::Internal`].
///
/// # Errors
///
/// Returns [`CryptoError::Internal`] if the file cannot be read.
#[cfg(feature = "std")]
pub fn hash_file_blake3(path: &std::path::Path) -> Result<[u8; 32], CryptoError> {
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|_| CryptoError::Internal("cannot open file"))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buf = alloc::vec![0u8; 65536];

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| CryptoError::Internal("file read error"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(*hasher.finalize().as_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SHAKE128 ──────────────────────────────────────────────────────────────

    #[test]
    fn shake128_nonzero_output() {
        let mut out = [0u8; 32];
        shake128(b"abc", &mut out);
        assert!(
            out.iter().any(|&b| b != 0),
            "SHAKE128 output must be non-zero"
        );
    }

    #[test]
    fn shake128_64_prefix_matches_32() {
        let mut out32 = [0u8; 32];
        let mut out64 = [0u8; 64];
        shake128(b"abc", &mut out32);
        shake128(b"abc", &mut out64);
        assert_eq!(
            out32,
            out64[..32],
            "64-byte SHAKE128 must be prefixed by 32-byte output"
        );
    }

    #[test]
    fn shake256_nonzero_output() {
        let mut out = [0u8; 32];
        shake256(b"abc", &mut out);
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn shake128_reader_matches_one_shot() {
        let mut expected = [0u8; 48];
        shake128(b"hello", &mut expected);

        let mut reader = shake128_start(b"hello");
        let mut actual = [0u8; 48];
        reader.read(&mut actual);
        assert_eq!(expected, actual);
    }

    // ── cSHAKE128 ─────────────────────────────────────────────────────────────

    #[test]
    fn cshake128_empty_equals_shake128() {
        let mut shake_out = [0u8; 32];
        let mut cshake_out = [0u8; 32];
        shake128(b"abc", &mut shake_out);
        cshake128(b"abc", b"", b"", &mut cshake_out);
        assert_eq!(
            shake_out, cshake_out,
            "cSHAKE128 with empty N and S must equal SHAKE128"
        );
    }

    #[test]
    fn cshake128_custom_differs_from_shake128() {
        let mut shake_out = [0u8; 32];
        let mut cshake_out = [0u8; 32];
        shake128(b"abc", &mut shake_out);
        cshake128(b"abc", b"Email Signature", b"", &mut cshake_out);
        assert_ne!(
            shake_out, cshake_out,
            "cSHAKE128 with non-empty N must differ from SHAKE128"
        );
    }

    #[test]
    fn cshake256_empty_equals_shake256() {
        let mut shake_out = [0u8; 64];
        let mut cshake_out = [0u8; 64];
        shake256(b"abc", &mut shake_out);
        cshake256(b"abc", b"", b"", &mut cshake_out);
        assert_eq!(
            shake_out, cshake_out,
            "cSHAKE256 with empty N and S must equal SHAKE256"
        );
    }

    #[test]
    fn cshake128_customization_matters() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        cshake128(b"abc", b"", b"customA", &mut out1);
        cshake128(b"abc", b"", b"customB", &mut out2);
        assert_ne!(
            out1, out2,
            "Different customization strings must produce different outputs"
        );
    }

    // ── TupleHash ──────────────────────────────────────────────────────────────

    #[test]
    fn tuple_hash128_unambiguous() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        tuple_hash128(&[b"ab", b"c"], b"", &mut out1).unwrap();
        tuple_hash128(&[b"a", b"bc"], b"", &mut out2).unwrap();
        assert_ne!(
            out1, out2,
            "TupleHash128 must disambiguate ('ab','c') from ('a','bc')"
        );
    }

    #[test]
    fn tuple_hash256_unambiguous() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        tuple_hash256(&[b"ab", b"c"], b"", &mut out1).unwrap();
        tuple_hash256(&[b"a", b"bc"], b"", &mut out2).unwrap();
        assert_ne!(
            out1, out2,
            "TupleHash256 must disambiguate ('ab','c') from ('a','bc')"
        );
    }

    #[test]
    fn tuple_hash128_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        tuple_hash128(&[b"hello", b"world"], b"custom", &mut out1).unwrap();
        tuple_hash128(&[b"hello", b"world"], b"custom", &mut out2).unwrap();
        assert_eq!(out1, out2, "TupleHash128 must be deterministic");
    }

    #[test]
    fn tuple_hash128_customization_matters() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        tuple_hash128(&[b"data"], b"custA", &mut out1).unwrap();
        tuple_hash128(&[b"data"], b"custB", &mut out2).unwrap();
        assert_ne!(
            out1, out2,
            "Different customizations must produce different TupleHash128 outputs"
        );
    }

    // ── Encoding helpers ────────────────────────────────────────────────────────

    #[test]
    fn left_encode_zero() {
        assert_eq!(left_encode(0), alloc::vec![1u8, 0u8]);
    }

    #[test]
    fn left_encode_one() {
        // 1 → 1 byte significant; value = 0x01
        assert_eq!(left_encode(1), alloc::vec![1u8, 1u8]);
    }

    #[test]
    fn right_encode_zero() {
        assert_eq!(right_encode(0), alloc::vec![0u8, 1u8]);
    }

    #[test]
    fn right_encode_one() {
        assert_eq!(right_encode(1), alloc::vec![1u8, 1u8]);
    }

    // ── BLAKE2b keyed ────────────────────────────────────────────────────────────

    #[test]
    fn blake2b_keyed_different_keys() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        blake2b_keyed(b"key1", b"message", &mut out1).unwrap();
        blake2b_keyed(b"key2", b"message", &mut out2).unwrap();
        assert_ne!(
            out1, out2,
            "Different keys must produce different BLAKE2b-keyed outputs"
        );
    }

    #[test]
    fn blake2b_keyed_different_messages() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        blake2b_keyed(b"key", b"message1", &mut out1).unwrap();
        blake2b_keyed(b"key", b"message2", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn blake2b_keyed_empty_key_rejected() {
        let mut out = [0u8; 32];
        assert_eq!(
            blake2b_keyed(b"", b"msg", &mut out).unwrap_err(),
            CryptoError::InvalidKey
        );
    }

    #[test]
    fn blake2b_keyed_too_long_key_rejected() {
        let mut out = [0u8; 32];
        assert_eq!(
            blake2b_keyed(&[0u8; 65], b"msg", &mut out).unwrap_err(),
            CryptoError::InvalidKey
        );
    }

    #[test]
    fn blake2b_keyed_empty_output_rejected() {
        assert_eq!(
            blake2b_keyed(b"key", b"msg", &mut []).unwrap_err(),
            CryptoError::BadInput
        );
    }

    #[test]
    fn blake2b_keyed_64byte_key_ok() {
        let mut out = [0u8; 64];
        blake2b_keyed(&[0x42u8; 64], b"hello", &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn blake2b_keyed_struct_api() {
        let key = b"my secret key";
        let msg = b"hello world";
        let mut out_fn = [0u8; 32];
        let mut out_struct = [0u8; 32];

        blake2b_keyed(key, msg, &mut out_fn).unwrap();
        Blake2bKeyed::new(key)
            .unwrap()
            .hash(msg, &mut out_struct)
            .unwrap();

        assert_eq!(
            out_fn, out_struct,
            "Free function and struct API must agree"
        );
    }

    #[test]
    fn blake2b_keyed_struct_empty_key_rejected() {
        assert_eq!(Blake2bKeyed::new(b"").unwrap_err(), CryptoError::InvalidKey);
    }

    // ── hash_file ─────────────────────────────────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn hash_file_sha256_matches_in_memory() {
        use sha2::Digest;
        use std::io::Write;

        let content = b"Hello, hash_file test!";

        let mut path = std::env::temp_dir();
        path.push("oxicrypto_hash_file_test.bin");

        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content).unwrap();
        }

        let expected = sha2::Sha256::digest(content);
        let actual = hash_file_sha256(&path).unwrap();

        assert_eq!(actual.as_slice(), expected.as_slice());

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_file_sha512_matches_in_memory() {
        use sha2::Digest;
        use std::io::Write;

        let content = b"SHA-512 file hash test";

        let mut path = std::env::temp_dir();
        path.push("oxicrypto_hash_file_sha512_test.bin");

        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content).unwrap();
        }

        let expected = sha2::Sha512::digest(content);
        let actual = hash_file_sha512(&path).unwrap();

        assert_eq!(actual.as_slice(), expected.as_slice());

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_file_blake3_matches_in_memory() {
        use std::io::Write;

        let content = b"BLAKE3 file hash test";

        let mut path = std::env::temp_dir();
        path.push("oxicrypto_hash_file_blake3_test.bin");

        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content).unwrap();
        }

        let expected = *blake3::hash(content).as_bytes();
        let actual = hash_file_blake3(&path).unwrap();

        assert_eq!(actual, expected);

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_file_sha256_not_found() {
        let path = std::env::temp_dir().join("oxicrypto_nonexistent_file_12345678.bin");
        let err = hash_file_sha256(&path).unwrap_err();
        assert!(matches!(err, CryptoError::Internal(_)));
    }
}
