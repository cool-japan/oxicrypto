//! HMAC implementations backed by `aws-lc-rs`.
//!
//! Supported algorithms: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512.

use aws_lc_rs::hmac as aws_hmac;
use oxicrypto_core::{CryptoError, Mac};

/// HMAC backed by `aws-lc-rs`.
///
/// Construct via [`AwsLcHmac::sha256`], [`AwsLcHmac::sha384`], or
/// [`AwsLcHmac::sha512`].
#[derive(Debug, Clone, Copy)]
pub struct AwsLcHmac {
    algorithm: aws_hmac::Algorithm,
    name: &'static str,
}

impl AwsLcHmac {
    /// HMAC using SHA-256 (32-byte tag).
    #[must_use]
    pub fn sha256() -> Self {
        Self {
            algorithm: aws_hmac::HMAC_SHA256,
            name: "HMAC-SHA-256 (aws-lc-rs)",
        }
    }

    /// HMAC using SHA-384 (48-byte tag).
    #[must_use]
    pub fn sha384() -> Self {
        Self {
            algorithm: aws_hmac::HMAC_SHA384,
            name: "HMAC-SHA-384 (aws-lc-rs)",
        }
    }

    /// HMAC using SHA-512 (64-byte tag).
    #[must_use]
    pub fn sha512() -> Self {
        Self {
            algorithm: aws_hmac::HMAC_SHA512,
            name: "HMAC-SHA-512 (aws-lc-rs)",
        }
    }
}

impl core::fmt::Display for AwsLcHmac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name)
    }
}

impl Mac for AwsLcHmac {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_len(&self) -> usize {
        // Recommended key length equals the digest output length.
        self.algorithm.digest_algorithm().output_len
    }

    fn output_len(&self) -> usize {
        self.algorithm.digest_algorithm().output_len
    }

    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let tag_len = self.output_len();
        if out.len() < tag_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let key_obj = aws_hmac::Key::new(self.algorithm, key);
        let tag = aws_hmac::sign(&key_obj, msg);
        out[..tag_len].copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let key_obj = aws_hmac::Key::new(self.algorithm, key);
        aws_hmac::verify(&key_obj, msg, tag).map_err(|_| CryptoError::InvalidTag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxicrypto_core::Mac;

    #[test]
    fn hmac_sha256_round_trip() {
        let hmac = AwsLcHmac::sha256();
        let key = [0x42u8; 32];
        let msg = b"hello hmac";
        let tag = hmac.mac_to_vec(&key, msg).expect("mac");
        assert_eq!(tag.len(), 32);
        hmac.verify(&key, msg, &tag).expect("verify");
    }

    #[test]
    fn hmac_sha384_round_trip() {
        let hmac = AwsLcHmac::sha384();
        let key = [0x11u8; 48];
        let msg = b"test message";
        let tag = hmac.mac_to_vec(&key, msg).expect("mac");
        assert_eq!(tag.len(), 48);
        hmac.verify(&key, msg, &tag).expect("verify");
    }

    #[test]
    fn hmac_sha512_round_trip() {
        let hmac = AwsLcHmac::sha512();
        let key = [0xabu8; 64];
        let msg = b"another message";
        let tag = hmac.mac_to_vec(&key, msg).expect("mac");
        assert_eq!(tag.len(), 64);
        hmac.verify(&key, msg, &tag).expect("verify");
    }

    #[test]
    fn hmac_wrong_tag_fails() {
        let hmac = AwsLcHmac::sha256();
        let key = [0x99u8; 32];
        let msg = b"some data";
        let mut tag = hmac.mac_to_vec(&key, msg).expect("mac");
        tag[0] ^= 0xff;
        assert_eq!(hmac.verify(&key, msg, &tag), Err(CryptoError::InvalidTag));
    }

    #[test]
    fn hmac_output_too_small() {
        let hmac = AwsLcHmac::sha256();
        let key = [0u8; 32];
        let msg = b"data";
        let mut out = [0u8; 10]; // too small for SHA-256
        assert_eq!(
            hmac.mac(&key, msg, &mut out),
            Err(CryptoError::BufferTooSmall)
        );
    }

    #[test]
    fn hmac_display() {
        assert_eq!(
            format!("{}", AwsLcHmac::sha256()),
            "HMAC-SHA-256 (aws-lc-rs)"
        );
    }
}
