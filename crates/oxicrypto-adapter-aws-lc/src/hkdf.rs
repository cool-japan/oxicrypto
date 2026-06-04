//! HKDF key-derivation backed by `aws-lc-rs`.
//!
//! Supported algorithms: HKDF-SHA-256, HKDF-SHA-384, HKDF-SHA-512.

use aws_lc_rs::hkdf::{self as aws_hkdf, KeyType};
use oxicrypto_core::{CryptoError, Kdf};

// ── KeyType adapter ───────────────────────────────────────────────────────────

/// A [`KeyType`] implementation that carries a fixed output length.
///
/// `aws-lc-rs` HKDF `Okm::fill` requires the buffer length to equal exactly
/// what was specified in `Prk::expand`. We wrap the desired length in this
/// newtype so we can pass it as the `len` parameter to `expand`.
struct OkmLen(usize);

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

// ── AwsLcHkdf ────────────────────────────────────────────────────────────────

/// HKDF backed by `aws-lc-rs`.
///
/// Construct via [`AwsLcHkdf::sha256`], [`AwsLcHkdf::sha384`], or
/// [`AwsLcHkdf::sha512`].
#[derive(Debug, Clone, Copy)]
pub struct AwsLcHkdf {
    algorithm: aws_hkdf::Algorithm,
    name: &'static str,
}

impl AwsLcHkdf {
    /// HKDF using HMAC-SHA-256.
    #[must_use]
    pub fn sha256() -> Self {
        Self {
            algorithm: aws_hkdf::HKDF_SHA256,
            name: "HKDF-SHA-256 (aws-lc-rs)",
        }
    }

    /// HKDF using HMAC-SHA-384.
    #[must_use]
    pub fn sha384() -> Self {
        Self {
            algorithm: aws_hkdf::HKDF_SHA384,
            name: "HKDF-SHA-384 (aws-lc-rs)",
        }
    }

    /// HKDF using HMAC-SHA-512.
    #[must_use]
    pub fn sha512() -> Self {
        Self {
            algorithm: aws_hkdf::HKDF_SHA512,
            name: "HKDF-SHA-512 (aws-lc-rs)",
        }
    }
}

impl core::fmt::Display for AwsLcHkdf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name)
    }
}

impl Kdf for AwsLcHkdf {
    fn name(&self) -> &'static str {
        self.name
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

        let salt_obj = aws_hkdf::Salt::new(self.algorithm, salt);
        let prk = salt_obj.extract(ikm);

        let info_slice = [info];
        let okm = prk
            .expand(&info_slice, OkmLen(okm_out.len()))
            .map_err(|_| CryptoError::BadInput)?;

        okm.fill(okm_out).map_err(|_| CryptoError::BadInput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxicrypto_core::Kdf;

    #[test]
    fn hkdf_sha256_basic() {
        let hkdf = AwsLcHkdf::sha256();
        let mut okm = [0u8; 32];
        hkdf.derive(b"input key", b"salt", b"info", &mut okm)
            .expect("derive");
        // Result must be non-zero
        assert_ne!(okm, [0u8; 32]);
    }

    #[test]
    fn hkdf_sha384_basic() {
        let hkdf = AwsLcHkdf::sha384();
        let mut okm = [0u8; 48];
        hkdf.derive(b"ikm", b"", b"", &mut okm).expect("derive");
        assert_ne!(okm, [0u8; 48]);
    }

    #[test]
    fn hkdf_sha512_basic() {
        let hkdf = AwsLcHkdf::sha512();
        let mut okm = [0u8; 64];
        hkdf.derive(b"ikm", b"salt", b"context", &mut okm)
            .expect("derive");
        assert_ne!(okm, [0u8; 64]);
    }

    #[test]
    fn hkdf_empty_output_is_bad_input() {
        let hkdf = AwsLcHkdf::sha256();
        let mut okm = [];
        assert_eq!(
            hkdf.derive(b"ikm", b"", b"", &mut okm),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn hkdf_display() {
        assert_eq!(
            format!("{}", AwsLcHkdf::sha256()),
            "HKDF-SHA-256 (aws-lc-rs)"
        );
    }
}
