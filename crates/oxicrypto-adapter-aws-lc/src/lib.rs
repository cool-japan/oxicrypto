//! `oxicrypto-adapter-aws-lc` — OxiCrypto adapter backed by `aws-lc-rs`.
//!
//! This crate exposes no types by default. Enable the `aws-lc` feature to
//! activate the AEAD, signature, hash, HKDF, and HMAC implementations backed
//! by the FIPS-validated `aws-lc-rs` library.
//!
//! # Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `aws-lc` | off | Enable aws-lc-rs backed implementations. |
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "aws-lc")]
//! # {
//! use oxicrypto_adapter_aws_lc::aead::AwsLcAead;
//! use oxicrypto_core::Aead;
//!
//! let cipher = AwsLcAead::aes256_gcm();
//! let key = vec![0u8; cipher.key_len()];
//! let nonce = vec![0u8; cipher.nonce_len()];
//! let mut ct = vec![0u8; 0 + cipher.tag_len()];
//! cipher.seal(&key, &nonce, b"", b"", &mut ct).expect("seal ok");
//! # }
//! ```

#[cfg(feature = "aws-lc")]
pub mod aead;

#[cfg(feature = "aws-lc")]
pub mod hash;

#[cfg(feature = "aws-lc")]
pub mod hkdf;

#[cfg(feature = "aws-lc")]
pub mod mac;

#[cfg(feature = "aws-lc")]
pub mod sign;

// ── AwsLcCryptoProvider ───────────────────────────────────────────────────────

/// Aggregate of all `aws-lc-rs` backed algorithm implementations.
///
/// Provides factory methods for all supported primitives. Useful for
/// dependency injection where you want to pass an aws-lc-rs provider
/// without importing individual types.
#[cfg(feature = "aws-lc")]
pub struct AwsLcCryptoProvider;

#[cfg(feature = "aws-lc")]
impl AwsLcCryptoProvider {
    // ── AEAD ──────────────────────────────────────────────────────────────────

    /// AES-128-GCM backed by aws-lc-rs.
    #[must_use]
    pub fn aes128_gcm() -> aead::AwsLcAead {
        aead::AwsLcAead::aes128_gcm()
    }

    /// AES-256-GCM backed by aws-lc-rs.
    #[must_use]
    pub fn aes256_gcm() -> aead::AwsLcAead {
        aead::AwsLcAead::aes256_gcm()
    }

    /// AES-256-GCM-SIV backed by aws-lc-rs.
    #[must_use]
    pub fn aes256_gcm_siv() -> aead::AwsLcAead {
        aead::AwsLcAead::aes256_gcm_siv()
    }

    /// ChaCha20-Poly1305 backed by aws-lc-rs.
    #[must_use]
    pub fn chacha20_poly1305() -> aead::AwsLcAead {
        aead::AwsLcAead::chacha20_poly1305()
    }

    // ── Hash ──────────────────────────────────────────────────────────────────

    /// SHA-256 backed by aws-lc-rs.
    #[must_use]
    pub fn sha256() -> hash::AwsLcSha256 {
        hash::AwsLcSha256
    }

    /// SHA-384 backed by aws-lc-rs.
    #[must_use]
    pub fn sha384() -> hash::AwsLcSha384 {
        hash::AwsLcSha384
    }

    /// SHA-512 backed by aws-lc-rs.
    #[must_use]
    pub fn sha512() -> hash::AwsLcSha512 {
        hash::AwsLcSha512
    }

    // ── Signer / Verifier ─────────────────────────────────────────────────────

    /// Ed25519 signer backed by aws-lc-rs.
    #[must_use]
    pub fn ed25519_signer() -> sign::AwsLcEd25519Signer {
        sign::AwsLcEd25519Signer
    }

    /// Ed25519 verifier backed by aws-lc-rs.
    #[must_use]
    pub fn ed25519_verifier() -> sign::AwsLcEd25519Verifier {
        sign::AwsLcEd25519Verifier
    }

    /// ECDSA-P256-SHA256 signer backed by aws-lc-rs.
    #[must_use]
    pub fn ecdsa_p256_signer() -> sign::AwsLcEcdsaP256Signer {
        sign::AwsLcEcdsaP256Signer
    }

    /// ECDSA-P256-SHA256 verifier backed by aws-lc-rs.
    #[must_use]
    pub fn ecdsa_p256_verifier() -> sign::AwsLcEcdsaP256Verifier {
        sign::AwsLcEcdsaP256Verifier
    }

    /// ECDSA-P384-SHA384 signer backed by aws-lc-rs.
    #[must_use]
    pub fn ecdsa_p384_signer() -> sign::AwsLcEcdsaP384Signer {
        sign::AwsLcEcdsaP384Signer
    }

    /// ECDSA-P384-SHA384 verifier backed by aws-lc-rs.
    #[must_use]
    pub fn ecdsa_p384_verifier() -> sign::AwsLcEcdsaP384Verifier {
        sign::AwsLcEcdsaP384Verifier
    }

    /// RSA-PKCS1-SHA256 signer backed by aws-lc-rs.
    #[must_use]
    pub fn rsa_pkcs1_sha256_signer() -> sign::AwsLcRsaPkcs1Sha256Signer {
        sign::AwsLcRsaPkcs1Sha256Signer
    }

    /// RSA-PSS-SHA256 signer backed by aws-lc-rs.
    #[must_use]
    pub fn rsa_pss_sha256_signer() -> sign::AwsLcRsaPssSha256Signer {
        sign::AwsLcRsaPssSha256Signer
    }

    /// RSA-PKCS1-SHA256 verifier backed by aws-lc-rs.
    #[must_use]
    pub fn rsa_pkcs1_sha256_verifier() -> sign::AwsLcRsaPkcs1Sha256Verifier {
        sign::AwsLcRsaPkcs1Sha256Verifier
    }

    /// RSA-PSS-SHA256 verifier backed by aws-lc-rs.
    #[must_use]
    pub fn rsa_pss_sha256_verifier() -> sign::AwsLcRsaPssSha256Verifier {
        sign::AwsLcRsaPssSha256Verifier
    }

    // ── KDF ───────────────────────────────────────────────────────────────────

    /// HKDF-SHA-256 backed by aws-lc-rs.
    #[must_use]
    pub fn hkdf_sha256() -> hkdf::AwsLcHkdf {
        hkdf::AwsLcHkdf::sha256()
    }

    /// HKDF-SHA-384 backed by aws-lc-rs.
    #[must_use]
    pub fn hkdf_sha384() -> hkdf::AwsLcHkdf {
        hkdf::AwsLcHkdf::sha384()
    }

    /// HKDF-SHA-512 backed by aws-lc-rs.
    #[must_use]
    pub fn hkdf_sha512() -> hkdf::AwsLcHkdf {
        hkdf::AwsLcHkdf::sha512()
    }

    // ── MAC ───────────────────────────────────────────────────────────────────

    /// HMAC-SHA-256 backed by aws-lc-rs.
    #[must_use]
    pub fn hmac_sha256() -> mac::AwsLcHmac {
        mac::AwsLcHmac::sha256()
    }

    /// HMAC-SHA-384 backed by aws-lc-rs.
    #[must_use]
    pub fn hmac_sha384() -> mac::AwsLcHmac {
        mac::AwsLcHmac::sha384()
    }

    /// HMAC-SHA-512 backed by aws-lc-rs.
    #[must_use]
    pub fn hmac_sha512() -> mac::AwsLcHmac {
        mac::AwsLcHmac::sha512()
    }
}
