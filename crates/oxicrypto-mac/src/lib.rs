#![forbid(unsafe_code)]

//! Pure Rust MAC implementations for the OxiCrypto stack.
//!
//! Provides [`Mac`] and [`StreamingMac`] trait wrappers for:
//! - HMAC-SHA-256 / SHA-384 / SHA-512 (one-shot + streaming + truncated)
//! - HMAC-SHA3-256 / SHA3-512
//! - Poly1305 (one-time MAC)
//! - CMAC-AES-128 / CMAC-AES-256
//! - KMAC128 / KMAC256 (SP 800-185, via `tiny-keccak`)
//!
//! All MAC verifications use constant-time comparison via the `subtle` crate.
//!
//! ## Hash-agnostic HMAC
//!
//! [`hmac_streaming_hash::StreamingHashHmac`] provides a generic HMAC adapter
//! that accepts any [`oxicrypto_core::StreamingHash`] implementation.
//!
//! ## Architecture: Internal Consistency with oxicrypto-kdf and oxicrypto-hash
//!
//! ### HKDF / PBKDF2 internal consistency
//!
//! `oxicrypto-kdf` (HKDF and PBKDF2) and `oxicrypto-mac` (HMAC) currently use
//! separate call paths to the same underlying `hmac` workspace crate. This is
//! an intentional architecture decision:
//!
//! - Both `oxicrypto-kdf` and `oxicrypto-mac` ultimately delegate to the same
//!   `hmac = "0.13"` crate — Cargo deduplicates the single copy at build time.
//!   Behavior is therefore byte-for-byte identical; there is no actual
//!   inconsistency in outputs.
//!
//! - Refactoring `oxicrypto-kdf` to route HKDF/PBKDF2 calls *through*
//!   `oxicrypto-mac`'s public `HmacSha256`/`HmacSha512` types would add a
//!   crate dependency edge (`oxicrypto-kdf` → `oxicrypto-mac`) and require
//!   plumbing the KDF trait bounds through the `Mac` trait boundary — a
//!   non-trivial refactor with no output correctness benefit (the outputs are
//!   already identical).
//!
//! - This is deferred as a post-1.0 ergonomic cleanup. Until then, callers
//!   that need HKDF-then-HMAC in the same context can use `oxicrypto-kdf`
//!   for key derivation and `oxicrypto-mac` for MAC computation independently,
//!   relying on the fact that both use the same underlying `hmac` implementation.
//!
//! ### KMAC / SHA3 sponge sharing
//!
//! `oxicrypto-mac` KMAC128/KMAC256 use `tiny-keccak 2.0.2` (with the `kmac`
//! feature), while `oxicrypto-hash` SHA3 uses the `sha3 0.12` crate. Both
//! implement the same Keccak-f\[1600\] permutation internally, so there is no
//! cryptographic inconsistency — the sponge state is not logically shared.
//!
//! Sharing the sponge context between crates would require either:
//! 1. Moving KMAC into `oxicrypto-hash` and re-exporting it from `oxicrypto-mac`, or
//! 2. Exposing `sha3` internal sponge state, which that crate deliberately does not.
//!
//! `tiny-keccak` is kept as the KMAC backend because it provides the correct
//! KMAC domain separation (pad byte `0x04` vs Keccak `0x01`) and the
//! SP 800-185-compliant `encode_string` / `bytepad` encoding. This is a
//! correct, tested, and auditable choice. The minor code-size duplication of
//! having two Keccak implementations is accepted as a pragmatic trade-off until
//! a unified SP 800-185 implementation is available in the `sha3` workspace dep.

extern crate alloc;

pub mod hmac_streaming_hash;
pub use hmac_streaming_hash::{
    hmac_with_streaming_hash, StreamingHashHmac, StreamingHashHmacSession,
};

use digest::KeyInit;
use hmac::Mac as HmacMac;
use oxicrypto_core::{CryptoError, Mac, StreamingMac};
use subtle::ConstantTimeEq;

// ── HMAC-SHA-256 ──────────────────────────────────────────────────────────────

/// HMAC-SHA-256 message authentication code (32-byte tag).
#[derive(Debug, Default, Clone, Copy)]
pub struct HmacSha256;

impl Mac for HmacSha256 {
    fn name(&self) -> &'static str {
        "HMAC-SHA-256"
    }
    fn key_len(&self) -> usize {
        32
    }
    fn output_len(&self) -> usize {
        32
    }
    fn min_key_len(&self) -> usize {
        32
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        out[..32].copy_from_slice(&result);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 32 {
            return Err(CryptoError::InvalidTag);
        }
        let mut expected = [0u8; 32];
        self.mac(key, msg, &mut expected)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl HmacSha256 {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 32;

    /// Create a pre-keyed HMAC-SHA-256 instance that implements [`StreamingMac`].
    pub fn new_keyed(key: &[u8]) -> Result<HmacSha256Keyed, CryptoError> {
        HmacSha256Keyed::new(key)
    }

    /// Compute a truncated HMAC-SHA-256 tag.
    ///
    /// Writes the first `out.len()` bytes of the full 32-byte HMAC into `out`.
    /// Returns [`CryptoError::BadInput`] if `out.len()` is outside `16..=32`
    /// (16 is the minimum safe truncation length per NIST SP 800-117; 32 is
    /// the full digest length).
    pub fn mac_truncated(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let n = out.len();
        if !(16..=32).contains(&n) {
            return Err(CryptoError::BadInput);
        }
        let mut full = [0u8; 32];
        self.mac(key, msg, &mut full)?;
        out.copy_from_slice(&full[..n]);
        Ok(())
    }

    /// Verify a truncated HMAC-SHA-256 tag in constant time.
    ///
    /// Returns [`CryptoError::BadInput`] if `tag.len()` is outside `16..=32`,
    /// or [`CryptoError::InvalidTag`] on mismatch.
    pub fn verify_truncated(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let n = tag.len();
        if !(16..=32).contains(&n) {
            return Err(CryptoError::BadInput);
        }
        let mut buf = [0u8; 32];
        self.mac(key, msg, &mut buf)?;
        if buf[..n].ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

// ── HMAC-SHA-512 ──────────────────────────────────────────────────────────────

/// HMAC-SHA-512 message authentication code (64-byte tag).
#[derive(Debug, Default, Clone, Copy)]
pub struct HmacSha512;

impl Mac for HmacSha512 {
    fn name(&self) -> &'static str {
        "HMAC-SHA-512"
    }
    fn key_len(&self) -> usize {
        64
    }
    fn output_len(&self) -> usize {
        64
    }
    fn min_key_len(&self) -> usize {
        64
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut mac =
            hmac::Hmac::<sha2::Sha512>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        out[..64].copy_from_slice(&result);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 64 {
            return Err(CryptoError::InvalidTag);
        }
        let mut expected = [0u8; 64];
        self.mac(key, msg, &mut expected)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl HmacSha512 {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 64;

    /// Create a pre-keyed HMAC-SHA-512 instance that implements [`StreamingMac`].
    pub fn new_keyed(key: &[u8]) -> Result<HmacSha512Keyed, CryptoError> {
        HmacSha512Keyed::new(key)
    }

    /// Compute a truncated HMAC-SHA-512 tag.
    ///
    /// Writes the first `out.len()` bytes of the full 64-byte HMAC into `out`.
    /// Returns [`CryptoError::BadInput`] if `out.len()` is outside `16..=64`.
    pub fn mac_truncated(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let n = out.len();
        if !(16..=64).contains(&n) {
            return Err(CryptoError::BadInput);
        }
        let mut full = [0u8; 64];
        self.mac(key, msg, &mut full)?;
        out.copy_from_slice(&full[..n]);
        Ok(())
    }

    /// Verify a truncated HMAC-SHA-512 tag in constant time.
    ///
    /// Returns [`CryptoError::BadInput`] if `tag.len()` is outside `16..=64`,
    /// or [`CryptoError::InvalidTag`] on mismatch.
    pub fn verify_truncated(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let n = tag.len();
        if !(16..=64).contains(&n) {
            return Err(CryptoError::BadInput);
        }
        let mut buf = [0u8; 64];
        self.mac(key, msg, &mut buf)?;
        if buf[..n].ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

// ── HMAC-SHA-384 ──────────────────────────────────────────────────────────────

/// HMAC-SHA-384 message authentication code (48-byte tag).
#[derive(Debug, Default, Clone, Copy)]
pub struct HmacSha384;

impl Mac for HmacSha384 {
    fn name(&self) -> &'static str {
        "HMAC-SHA-384"
    }
    fn key_len(&self) -> usize {
        48
    }
    fn output_len(&self) -> usize {
        48
    }
    fn min_key_len(&self) -> usize {
        48
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 48 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut mac =
            hmac::Hmac::<sha2::Sha384>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        out[..48].copy_from_slice(&result);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 48 {
            return Err(CryptoError::InvalidTag);
        }
        let mut expected = [0u8; 48];
        self.mac(key, msg, &mut expected)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl HmacSha384 {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 48;

    /// Create a pre-keyed HMAC-SHA-384 instance that implements [`StreamingMac`].
    pub fn new_keyed(key: &[u8]) -> Result<HmacSha384Keyed, CryptoError> {
        HmacSha384Keyed::new(key)
    }

    /// Compute a truncated HMAC-SHA-384 tag.
    ///
    /// Writes the first `out.len()` bytes of the full 48-byte HMAC into `out`.
    /// Returns [`CryptoError::BadInput`] if `out.len()` is outside `16..=48`.
    pub fn mac_truncated(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let n = out.len();
        if !(16..=48).contains(&n) {
            return Err(CryptoError::BadInput);
        }
        let mut full = [0u8; 48];
        self.mac(key, msg, &mut full)?;
        out.copy_from_slice(&full[..n]);
        Ok(())
    }

    /// Verify a truncated HMAC-SHA-384 tag in constant time.
    ///
    /// Returns [`CryptoError::BadInput`] if `tag.len()` is outside `16..=48`,
    /// or [`CryptoError::InvalidTag`] on mismatch.
    pub fn verify_truncated(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let n = tag.len();
        if !(16..=48).contains(&n) {
            return Err(CryptoError::BadInput);
        }
        let mut buf = [0u8; 48];
        self.mac(key, msg, &mut buf)?;
        if buf[..n].ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

// ── StreamingMac adapter (generic HMAC) ───────────────────────────────────────

/// Generic streaming MAC adapter wrapping `hmac::Hmac<D>`.
///
/// Implements [`StreamingMac`]: feed chunks with `update`, then consume with
/// `finalize` or `verify`.
pub struct HmacStreamingAdapter<D: hmac::digest::block_api::EagerHash>
where
    hmac::Hmac<D>: HmacMac + KeyInit,
{
    inner: hmac::Hmac<D>,
}

impl<D: hmac::digest::block_api::EagerHash> HmacStreamingAdapter<D>
where
    hmac::Hmac<D>: HmacMac + KeyInit,
{
    /// Create a new streaming adapter with the given key.
    ///
    /// Returns [`CryptoError::InvalidKey`] if the key is rejected by HMAC.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let inner = hmac::Hmac::<D>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { inner })
    }
}

impl<D: hmac::digest::block_api::EagerHash + Send> StreamingMac for HmacStreamingAdapter<D>
where
    hmac::Hmac<D>: HmacMac + KeyInit + Send,
{
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        let tag = self.inner.finalize().into_bytes();
        if out.len() < tag.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        out[..tag.len()].copy_from_slice(&tag);
        Ok(())
    }

    fn verify(self, expected: &[u8]) -> Result<(), CryptoError> {
        let tag = self.inner.finalize().into_bytes();
        if tag.len() != expected.len() {
            return Err(CryptoError::InvalidTag);
        }
        if tag.as_slice().ct_eq(expected).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

/// Streaming HMAC-SHA-256 adapter.
pub type HmacSha256Streaming = HmacStreamingAdapter<sha2::Sha256>;
/// Streaming HMAC-SHA-384 adapter.
pub type HmacSha384Streaming = HmacStreamingAdapter<sha2::Sha384>;
/// Streaming HMAC-SHA-512 adapter.
pub type HmacSha512Streaming = HmacStreamingAdapter<sha2::Sha512>;

// ── Pre-keyed HMAC types ──────────────────────────────────────────────────────

/// Pre-keyed HMAC-SHA-256 instance; implements [`StreamingMac`].
///
/// Created via [`HmacSha256::new_keyed`].  The key is bound at construction
/// time; subsequent calls to `update` feed message chunks, and `finalize` or
/// `verify` consume the instance.
pub struct HmacSha256Keyed(hmac::Hmac<sha2::Sha256>);

impl HmacSha256Keyed {
    /// Create a pre-keyed HMAC-SHA-256 instance.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl StreamingMac for HmacSha256Keyed {
    fn update(&mut self, data: &[u8]) {
        HmacMac::update(&mut self.0, data);
    }
    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        let result = HmacMac::finalize(self.0).into_bytes();
        if out.len() < result.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        out[..result.len()].copy_from_slice(&result);
        Ok(())
    }
    fn verify(self, expected: &[u8]) -> Result<(), CryptoError> {
        let tag = HmacMac::finalize(self.0).into_bytes();
        if tag.len() != expected.len() {
            return Err(CryptoError::InvalidTag);
        }
        if tag.as_slice().ct_eq(expected).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

/// Pre-keyed HMAC-SHA-512 instance; implements [`StreamingMac`].
///
/// Created via [`HmacSha512::new_keyed`].  The key is bound at construction
/// time; subsequent calls to `update` feed message chunks, and `finalize` or
/// `verify` consume the instance.
pub struct HmacSha512Keyed(hmac::Hmac<sha2::Sha512>);

impl HmacSha512Keyed {
    /// Create a pre-keyed HMAC-SHA-512 instance.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl StreamingMac for HmacSha512Keyed {
    fn update(&mut self, data: &[u8]) {
        HmacMac::update(&mut self.0, data);
    }
    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        let result = HmacMac::finalize(self.0).into_bytes();
        if out.len() < result.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        out[..result.len()].copy_from_slice(&result);
        Ok(())
    }
    fn verify(self, expected: &[u8]) -> Result<(), CryptoError> {
        let tag = HmacMac::finalize(self.0).into_bytes();
        if tag.len() != expected.len() {
            return Err(CryptoError::InvalidTag);
        }
        if tag.as_slice().ct_eq(expected).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

/// Pre-keyed HMAC-SHA-384 instance; implements [`StreamingMac`].
///
/// Created via [`HmacSha384::new_keyed`].  The key is bound at construction
/// time; subsequent calls to `update` feed message chunks, and `finalize` or
/// `verify` consume the instance.
pub struct HmacSha384Keyed(hmac::Hmac<sha2::Sha384>);

impl HmacSha384Keyed {
    /// Create a pre-keyed HMAC-SHA-384 instance.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl StreamingMac for HmacSha384Keyed {
    fn update(&mut self, data: &[u8]) {
        HmacMac::update(&mut self.0, data);
    }
    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        let result = HmacMac::finalize(self.0).into_bytes();
        if out.len() < result.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        out[..result.len()].copy_from_slice(&result);
        Ok(())
    }
    fn verify(self, expected: &[u8]) -> Result<(), CryptoError> {
        let tag = HmacMac::finalize(self.0).into_bytes();
        if tag.len() != expected.len() {
            return Err(CryptoError::InvalidTag);
        }
        if tag.as_slice().ct_eq(expected).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

// ── HMAC-SHA3-256 ─────────────────────────────────────────────────────────────

/// HMAC-SHA3-256 message authentication code (32-byte tag).
///
/// Uses `hmac::SimpleHmac` because sha3 0.12's types do not expose the
/// block-level `CoreProxy` trait required by `hmac::Hmac<D>`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HmacSha3_256;

impl Mac for HmacSha3_256 {
    fn name(&self) -> &'static str {
        "HMAC-SHA3-256"
    }
    fn key_len(&self) -> usize {
        32
    }
    fn output_len(&self) -> usize {
        32
    }
    fn min_key_len(&self) -> usize {
        32
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        use digest::KeyInit as _;

        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut mac = hmac::SimpleHmac::<sha3::Sha3_256>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;
        HmacMac::update(&mut mac, msg);
        let result = HmacMac::finalize(mac).into_bytes();
        out[..32].copy_from_slice(&result);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 32 {
            return Err(CryptoError::InvalidTag);
        }
        let mut expected = [0u8; 32];
        self.mac(key, msg, &mut expected)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl HmacSha3_256 {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 32;
}

// ── HMAC-SHA3-512 ─────────────────────────────────────────────────────────────

/// HMAC-SHA3-512 message authentication code (64-byte tag).
///
/// Uses `hmac::SimpleHmac` because sha3 0.12's types do not expose the
/// block-level `CoreProxy` trait required by `hmac::Hmac<D>`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HmacSha3_512;

impl Mac for HmacSha3_512 {
    fn name(&self) -> &'static str {
        "HMAC-SHA3-512"
    }
    fn key_len(&self) -> usize {
        64
    }
    fn output_len(&self) -> usize {
        64
    }
    fn min_key_len(&self) -> usize {
        64
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        use digest::KeyInit as _;

        if out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut mac = hmac::SimpleHmac::<sha3::Sha3_512>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;
        HmacMac::update(&mut mac, msg);
        let result = HmacMac::finalize(mac).into_bytes();
        out[..64].copy_from_slice(&result);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 64 {
            return Err(CryptoError::InvalidTag);
        }
        let mut expected = [0u8; 64];
        self.mac(key, msg, &mut expected)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl HmacSha3_512 {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 64;
}

// ── Poly1305 ──────────────────────────────────────────────────────────────────

/// Poly1305 one-time message authentication code (16-byte tag).
///
/// # Security warning
///
/// Poly1305 is a **one-time MAC**: the 32-byte key MUST NOT be reused for
/// different messages.  Re-use of the same key across messages completely
/// destroys the security guarantee.  In practice, derive a fresh per-message
/// key from a stream cipher (e.g. ChaCha20) or a KDF.
#[derive(Debug, Default, Clone, Copy)]
pub struct Poly1305Mac;

impl Mac for Poly1305Mac {
    fn name(&self) -> &'static str {
        "Poly1305"
    }
    fn key_len(&self) -> usize {
        32
    }
    fn output_len(&self) -> usize {
        16
    }
    fn min_key_len(&self) -> usize {
        32
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        use poly1305::universal_hash::KeyInit as _;

        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if out.len() < 16 {
            return Err(CryptoError::BufferTooSmall);
        }
        let key_arr = poly1305::Key::try_from(key).map_err(|_| CryptoError::InvalidKey)?;
        let mac = poly1305::Poly1305::new(&key_arr);
        // compute_unpadded is the standard Poly1305 MAC computation:
        // it adds a 0x01 high-bit to partial final blocks (per RFC 8439 §2.5).
        // update_padded would zero-pad partial blocks, which is incorrect for MAC.
        let tag = mac.compute_unpadded(msg);
        out[..16].copy_from_slice(tag.as_slice());
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 16 {
            return Err(CryptoError::InvalidTag);
        }
        let mut computed = [0u8; 16];
        self.mac(key, msg, &mut computed)?;
        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl Poly1305Mac {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 16;
}

// ── CMAC-AES-128 ──────────────────────────────────────────────────────────────

/// CMAC-AES-128 message authentication code (16-byte tag).
///
/// Uses `cmac 0.8` with `aes 0.9` (cipher 0.5 trait chain).
#[derive(Debug, Default, Clone, Copy)]
pub struct CmacAes128;

impl Mac for CmacAes128 {
    fn name(&self) -> &'static str {
        "CMAC-AES-128"
    }
    fn key_len(&self) -> usize {
        16
    }
    fn output_len(&self) -> usize {
        16
    }
    fn min_key_len(&self) -> usize {
        16
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        use digest::KeyInit as _;

        if out.len() < 16 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut mac = cmac::Cmac::<aes_cipher05::Aes128>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        out[..16].copy_from_slice(&result);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 16 {
            return Err(CryptoError::InvalidTag);
        }
        let mut expected = [0u8; 16];
        self.mac(key, msg, &mut expected)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl CmacAes128 {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 16;
}

// ── CMAC-AES-256 ──────────────────────────────────────────────────────────────

/// CMAC-AES-256 message authentication code (16-byte tag).
///
/// Uses `cmac 0.8` with `aes 0.9` (cipher 0.5 trait chain).
#[derive(Debug, Default, Clone, Copy)]
pub struct CmacAes256;

impl Mac for CmacAes256 {
    fn name(&self) -> &'static str {
        "CMAC-AES-256"
    }
    fn key_len(&self) -> usize {
        32
    }
    fn output_len(&self) -> usize {
        16
    }
    fn min_key_len(&self) -> usize {
        32
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        use digest::KeyInit as _;

        if out.len() < 16 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut mac = cmac::Cmac::<aes_cipher05::Aes256>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        out[..16].copy_from_slice(&result);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != 16 {
            return Err(CryptoError::InvalidTag);
        }
        let mut expected = [0u8; 16];
        self.mac(key, msg, &mut expected)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

impl CmacAes256 {
    /// Tag length in bytes.
    pub const OUTPUT_LEN: usize = 16;
}

// ── KMAC128 ───────────────────────────────────────────────────────────────────

/// KMAC128 message authentication code (SP 800-185).
///
/// Variable-length output; the default output length is 32 bytes.
/// Uses a customization string (may be empty) for domain separation.
pub struct Kmac128 {
    /// Customization string for domain separation (SP 800-185 §3.3).
    custom: alloc::vec::Vec<u8>,
    /// Output tag length in bytes (minimum 1, default 32).
    output_len: usize,
}

impl Kmac128 {
    /// Create a new KMAC128 with the given customization string and output length.
    ///
    /// Returns [`CryptoError::BadInput`] if `output_len` is 0.
    pub fn new(custom: &[u8], output_len: usize) -> Result<Self, CryptoError> {
        if output_len == 0 {
            return Err(CryptoError::BadInput);
        }
        Ok(Self {
            custom: custom.to_vec(),
            output_len,
        })
    }
}

impl core::fmt::Debug for Kmac128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kmac128")
            .field("output_len", &self.output_len)
            .finish()
    }
}

impl Mac for Kmac128 {
    fn name(&self) -> &'static str {
        "KMAC128"
    }
    fn key_len(&self) -> usize {
        // KMAC accepts variable-length keys; recommend >= 16 bytes.
        16
    }
    fn output_len(&self) -> usize {
        self.output_len
    }
    fn min_key_len(&self) -> usize {
        16
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        use tiny_keccak::Hasher as _;
        if out.len() < self.output_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut kmac = tiny_keccak::Kmac::v128(key, &self.custom);
        kmac.update(msg);
        kmac.finalize(&mut out[..self.output_len]);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != self.output_len {
            return Err(CryptoError::InvalidTag);
        }
        let mut computed = alloc::vec![0u8; self.output_len];
        self.mac(key, msg, &mut computed)?;
        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

// ── KMAC256 ───────────────────────────────────────────────────────────────────

/// KMAC256 message authentication code (SP 800-185).
///
/// Variable-length output; the default output length is 64 bytes.
/// Uses a customization string (may be empty) for domain separation.
pub struct Kmac256 {
    /// Customization string for domain separation.
    custom: alloc::vec::Vec<u8>,
    /// Output tag length in bytes (minimum 1, default 64).
    output_len: usize,
}

impl Kmac256 {
    /// Create a new KMAC256 with the given customization string and output length.
    ///
    /// Returns [`CryptoError::BadInput`] if `output_len` is 0.
    pub fn new(custom: &[u8], output_len: usize) -> Result<Self, CryptoError> {
        if output_len == 0 {
            return Err(CryptoError::BadInput);
        }
        Ok(Self {
            custom: custom.to_vec(),
            output_len,
        })
    }
}

impl core::fmt::Debug for Kmac256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kmac256")
            .field("output_len", &self.output_len)
            .finish()
    }
}

impl Mac for Kmac256 {
    fn name(&self) -> &'static str {
        "KMAC256"
    }
    fn key_len(&self) -> usize {
        32
    }
    fn output_len(&self) -> usize {
        self.output_len
    }
    fn min_key_len(&self) -> usize {
        16
    }
    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        use tiny_keccak::Hasher as _;
        if out.len() < self.output_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut kmac = tiny_keccak::Kmac::v256(key, &self.custom);
        kmac.update(msg);
        kmac.finalize(&mut out[..self.output_len]);
        Ok(())
    }
    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if tag.len() != self.output_len {
            return Err(CryptoError::InvalidTag);
        }
        let mut computed = alloc::vec![0u8; self.output_len];
        self.mac(key, msg, &mut computed)?;
        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

// ── KMAC-XOF free functions ───────────────────────────────────────────────────

/// KMAC128 with variable-length output (XOF mode, SP 800-185 §4.3.1).
///
/// Convenience free function returning an owned `Vec<u8>`.  For structured
/// use with the [`Mac`] trait, see [`Kmac128`] which already accepts any
/// output length.
///
/// - `key`: KMAC key (recommended ≥ 16 bytes for 128-bit security)
/// - `custom`: customization string (e.g. `b"my-app-context"`), may be empty
/// - `msg`: message data
/// - `output_len`: desired output length in bytes
///
/// Returns [`CryptoError::BadInput`] if `output_len == 0`.
pub fn kmac128_xof(
    key: &[u8],
    custom: &[u8],
    msg: &[u8],
    output_len: usize,
) -> Result<alloc::vec::Vec<u8>, CryptoError> {
    use tiny_keccak::Hasher as _;
    if output_len == 0 {
        return Err(CryptoError::BadInput);
    }
    let mut k = tiny_keccak::Kmac::v128(key, custom);
    k.update(msg);
    let mut out = alloc::vec![0u8; output_len];
    k.finalize(&mut out);
    Ok(out)
}

/// KMAC256 with variable-length output (XOF mode, SP 800-185 §4.3.1).
///
/// Convenience free function returning an owned `Vec<u8>`.  For structured
/// use with the [`Mac`] trait, see [`Kmac256`] which already accepts any
/// output length.
///
/// - `key`: KMAC key (recommended ≥ 32 bytes for 256-bit security)
/// - `custom`: customization string (e.g. `b"my-app-context"`), may be empty
/// - `msg`: message data
/// - `output_len`: desired output length in bytes
///
/// Returns [`CryptoError::BadInput`] if `output_len == 0`.
pub fn kmac256_xof(
    key: &[u8],
    custom: &[u8],
    msg: &[u8],
    output_len: usize,
) -> Result<alloc::vec::Vec<u8>, CryptoError> {
    use tiny_keccak::Hasher as _;
    if output_len == 0 {
        return Err(CryptoError::BadInput);
    }
    let mut k = tiny_keccak::Kmac::v256(key, custom);
    k.update(msg);
    let mut out = alloc::vec![0u8; output_len];
    k.finalize(&mut out);
    Ok(out)
}

// ── BLAKE3 keyed-hash MAC ─────────────────────────────────────────────────────

/// BLAKE3 keyed-hash MAC (BLAKE3 spec §2.7).
///
/// This is BLAKE3's **native** authentication mode, **not** HMAC with BLAKE3.
/// The key must be exactly 32 bytes.  Output is always 32 bytes.
///
/// This is faster than [`hmac_sha256_to_vec`] at an equivalent security level
/// because BLAKE3 uses a single-pass tree construction rather than the
/// double-compression of HMAC.
///
/// Use [`blake3_keyed_mac_verify`] for constant-time verification.
pub fn blake3_keyed_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_keyed(key)
        .update(msg)
        .finalize()
        .as_bytes()
}

/// Verify a BLAKE3 keyed-hash MAC in constant time.
///
/// Returns `Ok(())` when `expected` matches the BLAKE3 keyed-hash of `msg`
/// under `key`, or [`CryptoError::InvalidTag`] on mismatch.
pub fn blake3_keyed_mac_verify(
    key: &[u8; 32],
    msg: &[u8],
    expected: &[u8; 32],
) -> Result<(), CryptoError> {
    let actual = blake3_keyed_mac(key, msg);
    if actual.ct_eq(expected).into() {
        Ok(())
    } else {
        Err(CryptoError::InvalidTag)
    }
}

// ── Standalone truncated-verify helper ───────────────────────────────────────

/// Verify the first `truncated_tag.len()` bytes of an HMAC-SHA-256 MAC.
///
/// Useful for protocols that truncate MAC tags (e.g. to 16 bytes for bandwidth
/// savings).  Always performs constant-time comparison over exactly
/// `truncated_tag.len()` bytes.
///
/// Note: this helper accepts tags as short as 1 byte (permissive API for
/// protocol use).  For production use, prefer [`HmacSha256::verify_truncated`]
/// which enforces a 16-byte minimum per NIST SP 800-117.
///
/// Returns [`CryptoError::BadInput`] if `truncated_tag` is empty or longer
/// than 32 bytes.
pub fn hmac_sha256_verify_truncated(
    key: &[u8],
    msg: &[u8],
    truncated_tag: &[u8],
) -> Result<(), CryptoError> {
    if truncated_tag.is_empty() || truncated_tag.len() > 32 {
        return Err(CryptoError::BadInput);
    }
    let mut buf = [0u8; 32];
    HmacSha256.mac(key, msg, &mut buf)?;
    if buf[..truncated_tag.len()].ct_eq(truncated_tag).into() {
        Ok(())
    } else {
        Err(CryptoError::InvalidTag)
    }
}

// ── TLS MAC negotiation (see src/tls.rs) ─────────────────────────────────────

/// TLS cipher suite → MAC negotiation.
///
/// See [`TlsCipherSuite`], [`negotiate_mac`], and [`mac_name_for_suite`].
pub mod tls;
pub use tls::{mac_name_for_suite, negotiate_mac, TlsCipherSuite};

// ── Convenience: mac_to_vec helpers ──────────────────────────────────────────

/// Compute an HMAC-SHA-256 tag and return it as a 32-byte [`Vec<u8>`].
///
/// This is a convenience wrapper around [`HmacSha256::mac`] for callers that
/// prefer an owned return value over a pre-allocated output buffer.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if the HMAC crate rejects the key.
#[must_use = "MAC result must be used or verified"]
pub fn hmac_sha256_to_vec(key: &[u8], msg: &[u8]) -> Result<alloc::vec::Vec<u8>, CryptoError> {
    let mut out = alloc::vec![0u8; 32];
    HmacSha256.mac(key, msg, &mut out)?;
    Ok(out)
}

/// Compute an HMAC-SHA-384 tag and return it as a 48-byte [`Vec<u8>`].
///
/// This is a convenience wrapper around [`HmacSha384::mac`] for callers that
/// prefer an owned return value over a pre-allocated output buffer.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if the HMAC crate rejects the key.
#[must_use = "MAC result must be used or verified"]
pub fn hmac_sha384_to_vec(key: &[u8], msg: &[u8]) -> Result<alloc::vec::Vec<u8>, CryptoError> {
    let mut out = alloc::vec![0u8; 48];
    HmacSha384.mac(key, msg, &mut out)?;
    Ok(out)
}

/// Compute an HMAC-SHA-512 tag and return it as a 64-byte [`Vec<u8>`].
///
/// This is a convenience wrapper around [`HmacSha512::mac`] for callers that
/// prefer an owned return value over a pre-allocated output buffer.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if the HMAC crate rejects the key.
#[must_use = "MAC result must be used or verified"]
pub fn hmac_sha512_to_vec(key: &[u8], msg: &[u8]) -> Result<alloc::vec::Vec<u8>, CryptoError> {
    let mut out = alloc::vec![0u8; 64];
    HmacSha512.mac(key, msg, &mut out)?;
    Ok(out)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests_inline.rs");
}
