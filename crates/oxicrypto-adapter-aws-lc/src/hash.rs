//! Hash implementations backed by `aws-lc-rs`.
//!
//! Supported algorithms: SHA-256, SHA-384, SHA-512.

use aws_lc_rs::digest::{self, SHA256, SHA384, SHA512};
use oxicrypto_core::{CryptoError, Hash};

/// SHA-256 hash backed by `aws-lc-rs` (32-byte output).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcSha256;

/// SHA-384 hash backed by `aws-lc-rs` (48-byte output).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcSha384;

/// SHA-512 hash backed by `aws-lc-rs` (64-byte output).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcSha512;

fn hash_with_algo(
    algorithm: &'static digest::Algorithm,
    msg: &[u8],
    out: &mut [u8],
    expected_len: usize,
) -> Result<(), CryptoError> {
    if out.len() < expected_len {
        return Err(CryptoError::BufferTooSmall);
    }
    let d = digest::digest(algorithm, msg);
    out[..expected_len].copy_from_slice(d.as_ref());
    Ok(())
}

impl Hash for AwsLcSha256 {
    fn name(&self) -> &'static str {
        "SHA-256 (aws-lc-rs)"
    }
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        hash_with_algo(&SHA256, msg, out, 32)
    }
}

impl Hash for AwsLcSha384 {
    fn name(&self) -> &'static str {
        "SHA-384 (aws-lc-rs)"
    }
    fn output_len(&self) -> usize {
        48
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        hash_with_algo(&SHA384, msg, out, 48)
    }
}

impl Hash for AwsLcSha512 {
    fn name(&self) -> &'static str {
        "SHA-512 (aws-lc-rs)"
    }
    fn output_len(&self) -> usize {
        64
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        hash_with_algo(&SHA512, msg, out, 64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxicrypto_core::Hash;

    #[test]
    fn sha256_known_length() {
        let h = AwsLcSha256;
        let out = h.hash_to_vec(b"hello").expect("hash");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn sha384_known_length() {
        let h = AwsLcSha384;
        let out = h.hash_to_vec(b"hello").expect("hash");
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn sha512_known_length() {
        let h = AwsLcSha512;
        let out = h.hash_to_vec(b"hello").expect("hash");
        assert_eq!(out.len(), 64);
    }
}
