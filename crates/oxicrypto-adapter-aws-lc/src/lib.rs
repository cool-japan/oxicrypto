//! `oxicrypto-adapter-aws-lc` — OxiCrypto adapter backed by `aws-lc-rs`.
//!
//! This crate exposes no types by default. Enable the `aws-lc` feature to
//! activate the AEAD, signature, and hash implementations backed by the
//! FIPS-validated `aws-lc-rs` library.
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
pub mod sign;
