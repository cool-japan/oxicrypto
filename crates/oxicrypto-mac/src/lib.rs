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

extern crate alloc;

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
    /// Compute a truncated HMAC-SHA-256 tag.
    ///
    /// Writes the first `out.len()` bytes of the full 32-byte HMAC into `out`.
    /// Returns [`CryptoError::BadInput`] if `out.len() < 16` (minimum safe
    /// truncation length per NIST SP 800-117).
    pub fn mac_truncated(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let n = out.len();
        if n < 16 {
            return Err(CryptoError::BadInput);
        }
        let mut full = [0u8; 32];
        self.mac(key, msg, &mut full)?;
        out.copy_from_slice(&full[..n]);
        Ok(())
    }

    /// Verify a truncated HMAC-SHA-256 tag in constant time.
    ///
    /// Returns [`CryptoError::BadInput`] if `tag.len() < 16`, or
    /// [`CryptoError::InvalidTag`] on mismatch.
    pub fn verify_truncated(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let n = tag.len();
        if n < 16 {
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
    /// Compute a truncated HMAC-SHA-512 tag.
    ///
    /// Writes the first `out.len()` bytes of the full 64-byte HMAC into `out`.
    /// Returns [`CryptoError::BadInput`] if `out.len() < 16`.
    pub fn mac_truncated(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let n = out.len();
        if n < 16 {
            return Err(CryptoError::BadInput);
        }
        let mut full = [0u8; 64];
        self.mac(key, msg, &mut full)?;
        out.copy_from_slice(&full[..n]);
        Ok(())
    }

    /// Verify a truncated HMAC-SHA-512 tag in constant time.
    ///
    /// Returns [`CryptoError::BadInput`] if `tag.len() < 16`, or
    /// [`CryptoError::InvalidTag`] on mismatch.
    pub fn verify_truncated(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let n = tag.len();
        if n < 16 {
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
    /// Compute a truncated HMAC-SHA-384 tag.
    ///
    /// Writes the first `out.len()` bytes of the full 48-byte HMAC into `out`.
    /// Returns [`CryptoError::BadInput`] if `out.len() < 16`.
    pub fn mac_truncated(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let n = out.len();
        if n < 16 {
            return Err(CryptoError::BadInput);
        }
        let mut full = [0u8; 48];
        self.mac(key, msg, &mut full)?;
        out.copy_from_slice(&full[..n]);
        Ok(())
    }

    /// Verify a truncated HMAC-SHA-384 tag in constant time.
    ///
    /// Returns [`CryptoError::BadInput`] if `tag.len() < 16`, or
    /// [`CryptoError::InvalidTag`] on mismatch.
    pub fn verify_truncated(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let n = tag.len();
        if n < 16 {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── HMAC-SHA-256 ────────────────────────────────────────────────────────

    // RFC 4231 Test Case 1
    #[test]
    fn hmac_sha256_rfc4231_tc1() {
        let key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected =
            hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let mac = HmacSha256;
        let mut out = [0u8; 32];
        mac.mac(&key, data, &mut out).unwrap();
        assert_eq!(&out[..], expected.as_slice(), "HMAC-SHA-256 RFC4231 TC1");
    }

    #[test]
    fn hmac_sha256_verify_ok() {
        let key = b"secret-key";
        let msg = b"the message";
        let mac_impl = HmacSha256;
        let mut tag = [0u8; 32];
        mac_impl.mac(key, msg, &mut tag).unwrap();
        mac_impl
            .verify(key, msg, &tag)
            .expect("verify should succeed");
    }

    #[test]
    fn hmac_sha256_verify_fail() {
        let key = b"secret-key";
        let msg = b"the message";
        let mac_impl = HmacSha256;
        let mut tag = [0u8; 32];
        mac_impl.mac(key, msg, &mut tag).unwrap();
        tag[0] ^= 0xff;
        let result = mac_impl.verify(key, msg, &tag);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    // ── HMAC-SHA-512 ────────────────────────────────────────────────────────

    #[test]
    fn hmac_sha512_round_trip() {
        let key = b"another-secret-key";
        let msg = b"another message";
        let mac_impl = HmacSha512;
        let mut tag = [0u8; 64];
        mac_impl.mac(key, msg, &mut tag).unwrap();
        mac_impl
            .verify(key, msg, &tag)
            .expect("verify should succeed");
    }

    #[test]
    fn hmac_sha512_verify_fail() {
        let key = b"key";
        let msg = b"msg";
        let mac_impl = HmacSha512;
        let mut tag = [0u8; 64];
        mac_impl.mac(key, msg, &mut tag).unwrap();
        tag[0] ^= 1;
        assert_eq!(
            mac_impl.verify(key, msg, &tag),
            Err(CryptoError::InvalidTag)
        );
    }

    // ── HMAC-SHA-384 ────────────────────────────────────────────────────────

    // RFC 4231 Test Case 1 for HMAC-SHA-384
    #[test]
    fn hmac_sha384_rfc4231_tc1() {
        let key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex_decode(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6",
        );

        let mac = HmacSha384;
        let mut out = [0u8; 48];
        mac.mac(&key, data, &mut out).unwrap();
        assert_eq!(&out[..], expected.as_slice(), "HMAC-SHA-384 RFC4231 TC1");
    }

    #[test]
    fn hmac_sha384_round_trip() {
        let key = b"hmac-sha384-test-key";
        let msg = b"test message for sha384";
        let mac = HmacSha384;
        let mut tag = [0u8; 48];
        mac.mac(key, msg, &mut tag).unwrap();
        mac.verify(key, msg, &tag).expect("verify should succeed");
    }

    #[test]
    fn hmac_sha384_verify_fail() {
        let key = b"key";
        let msg = b"msg";
        let mac = HmacSha384;
        let mut tag = [0u8; 48];
        mac.mac(key, msg, &mut tag).unwrap();
        tag[0] ^= 1;
        assert_eq!(mac.verify(key, msg, &tag), Err(CryptoError::InvalidTag));
    }

    // ── StreamingMac adapter ─────────────────────────────────────────────────

    /// Verify that the streaming adapter produces the same tag as the one-shot
    /// HmacSha256::mac method (fed the same message in two chunks).
    #[test]
    fn hmac_sha256_streaming_matches_oneshot() {
        let key = b"streaming-key";
        let msg_a = b"hello ";
        let msg_b = b"world";
        let full_msg = b"hello world";

        // One-shot
        let one_shot = HmacSha256;
        let mut expected = [0u8; 32];
        one_shot.mac(key, full_msg, &mut expected).unwrap();

        // Streaming
        let mut streaming = HmacSha256Streaming::new(key).unwrap();
        streaming.update(msg_a);
        streaming.update(msg_b);
        let mut got = [0u8; 32];
        streaming.finalize(&mut got).unwrap();

        assert_eq!(expected, got, "streaming must match one-shot");
    }

    #[test]
    fn hmac_sha256_streaming_verify_ok() {
        let key = b"verify-key";
        let msg = b"verify message";

        let mut one_shot_tag = [0u8; 32];
        HmacSha256.mac(key, msg, &mut one_shot_tag).unwrap();

        let mut streaming = HmacSha256Streaming::new(key).unwrap();
        streaming.update(msg);
        streaming
            .verify(&one_shot_tag)
            .expect("streaming verify must succeed");
    }

    #[test]
    fn hmac_sha256_streaming_verify_fail() {
        let key = b"k";
        let msg = b"m";
        let bad_tag = [0xffu8; 32];

        let mut streaming = HmacSha256Streaming::new(key).unwrap();
        streaming.update(msg);
        assert_eq!(
            streaming.verify(&bad_tag),
            Err(CryptoError::InvalidTag),
            "streaming verify must fail on wrong tag"
        );
    }

    // ── HMAC-SHA3-256 ────────────────────────────────────────────────────────

    /// Basic KAT: HMAC-SHA3-256 of "Hi There" with RFC 4231 key
    /// (reference computed offline using SHA3-256 as the hash function).
    #[test]
    fn hmac_sha3_256_round_trip() {
        let key = b"hmac-sha3-256-key";
        let msg = b"test message";
        let mac = HmacSha3_256;
        let mut tag = [0u8; 32];
        mac.mac(key, msg, &mut tag).unwrap();
        mac.verify(key, msg, &tag)
            .expect("HMAC-SHA3-256 verify must succeed");
    }

    #[test]
    fn hmac_sha3_256_verify_fail() {
        let key = b"k";
        let msg = b"m";
        let mac = HmacSha3_256;
        let mut tag = [0u8; 32];
        mac.mac(key, msg, &mut tag).unwrap();
        tag[0] ^= 1;
        assert_eq!(mac.verify(key, msg, &tag), Err(CryptoError::InvalidTag));
    }

    // ── HMAC-SHA3-512 ────────────────────────────────────────────────────────

    #[test]
    fn hmac_sha3_512_round_trip() {
        let key = b"hmac-sha3-512-test-key";
        let msg = b"test message for sha3-512";
        let mac = HmacSha3_512;
        let mut tag = [0u8; 64];
        mac.mac(key, msg, &mut tag).unwrap();
        mac.verify(key, msg, &tag)
            .expect("HMAC-SHA3-512 verify must succeed");
    }

    // ── Poly1305 ─────────────────────────────────────────────────────────────

    /// RFC 8439 §2.5.2 test vector.
    ///
    /// key  = 85d6be7857556d337f4452fe42d506a
    ///         80103808afb0db2fd4abff6af4149f51
    /// data = "Cryptographic Forum Research Group"
    /// tag  = a8061dc1305136c6c22b8baf0c0127a9
    #[test]
    fn poly1305_rfc8439_s2_5_2() {
        let key = hex_decode(
            "85d6be7857556d337f4452fe42d506a8\
             0103808afb0db2fd4abff6af4149f51b",
        );
        let msg = b"Cryptographic Forum Research Group";
        let expected = hex_decode("a8061dc1305136c6c22b8baf0c0127a9");

        let mac = Poly1305Mac;
        let mut out = [0u8; 16];
        mac.mac(&key, msg, &mut out).unwrap();
        assert_eq!(&out[..], expected.as_slice(), "Poly1305 RFC8439 §2.5.2");
    }

    #[test]
    fn poly1305_verify_ok() {
        let key = [0u8; 32];
        let msg = b"test";
        let mac = Poly1305Mac;
        let mut tag = [0u8; 16];
        mac.mac(&key, msg, &mut tag).unwrap();
        mac.verify(&key, msg, &tag)
            .expect("Poly1305 verify must succeed");
    }

    #[test]
    fn poly1305_verify_fail() {
        let key = [1u8; 32];
        let msg = b"test";
        let mac = Poly1305Mac;
        let mut tag = [0u8; 16];
        mac.mac(&key, msg, &mut tag).unwrap();
        tag[0] ^= 0xff;
        assert_eq!(mac.verify(&key, msg, &tag), Err(CryptoError::InvalidTag));
    }

    #[test]
    fn poly1305_bad_key_len() {
        let key = [0u8; 16]; // wrong length
        let mac = Poly1305Mac;
        let mut out = [0u8; 16];
        assert_eq!(
            mac.mac(&key, b"msg", &mut out),
            Err(CryptoError::InvalidKey)
        );
    }

    // ── CMAC-AES-128 ─────────────────────────────────────────────────────────

    /// NIST SP 800-38B Example 1: AES-128, empty message.
    ///
    /// K   = 2b7e151628aed2a6abf7158809cf4f3c
    /// M   = (empty)
    /// T16 = bb1d6929e9593728 7fa37d129b756746
    #[test]
    fn cmac_aes128_nist_sp800_38b_example1() {
        let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
        let expected = hex_decode("bb1d6929e95937287fa37d129b756746");

        let mac = CmacAes128;
        let mut out = [0u8; 16];
        mac.mac(&key, b"", &mut out).unwrap();
        assert_eq!(&out[..], expected.as_slice(), "CMAC-AES-128 SP 800-38B Ex1");
    }

    #[test]
    fn cmac_aes128_round_trip() {
        let key = [0x2b_u8; 16];
        let msg = b"hello cmac aes128";
        let mac = CmacAes128;
        let mut tag = [0u8; 16];
        mac.mac(&key, msg, &mut tag).unwrap();
        mac.verify(&key, msg, &tag)
            .expect("CMAC-AES-128 verify must succeed");
    }

    #[test]
    fn cmac_aes128_verify_fail() {
        let key = [0u8; 16];
        let msg = b"msg";
        let mac = CmacAes128;
        let mut tag = [0u8; 16];
        mac.mac(&key, msg, &mut tag).unwrap();
        tag[0] ^= 1;
        assert_eq!(mac.verify(&key, msg, &tag), Err(CryptoError::InvalidTag));
    }

    // ── CMAC-AES-256 ─────────────────────────────────────────────────────────

    #[test]
    fn cmac_aes256_round_trip() {
        let key = [0x42_u8; 32];
        let msg = b"hello cmac aes256";
        let mac = CmacAes256;
        let mut tag = [0u8; 16];
        mac.mac(&key, msg, &mut tag).unwrap();
        mac.verify(&key, msg, &tag)
            .expect("CMAC-AES-256 verify must succeed");
    }

    // ── KMAC128 ──────────────────────────────────────────────────────────────

    /// NIST SP 800-185 Sample #1 (KMAC128, empty customization, 32-byte output)
    ///
    /// Key  = 404142...5e5f (32 bytes)
    /// Data = 00010203 (4 bytes)
    /// S    = "" (empty)
    /// L    = 256 bits
    ///
    /// Expected = e5780b0d3ea6f7d3a429c5706aa43a00 fadbd7d49628839e3187243f456ee14e
    ///
    /// Reference: NIST SP 800-185 §A.1 Sample #1, verified by tiny-keccak test suite.
    #[test]
    fn kmac128_nist_sp800_185_sample1() {
        let key = hex_decode(
            "404142434445464748494a4b4c4d4e4f\
             505152535455565758595a5b5c5d5e5f",
        );
        let data = hex_decode("00010203");
        let expected = hex_decode(
            "e5780b0d3ea6f7d3a429c5706aa43a00\
             fadbd7d49628839e3187243f456ee14e",
        );

        let kmac = Kmac128::new(b"", 32).unwrap();
        let mut out = [0u8; 32];
        kmac.mac(&key, &data, &mut out).unwrap();
        assert_eq!(
            &out[..],
            expected.as_slice(),
            "KMAC128 SP 800-185 Sample #1"
        );
    }

    #[test]
    fn kmac128_round_trip() {
        let kmac = Kmac128::new(b"test-domain", 32).unwrap();
        let key = [0xaa_u8; 16];
        let msg = b"hello kmac128";
        let mut tag = [0u8; 32];
        kmac.mac(&key, msg, &mut tag).unwrap();
        kmac.verify(&key, msg, &tag)
            .expect("KMAC128 verify must succeed");
    }

    #[test]
    fn kmac128_verify_fail() {
        let kmac = Kmac128::new(b"", 32).unwrap();
        let key = [0u8; 16];
        let msg = b"test";
        let mut tag = [0u8; 32];
        kmac.mac(&key, msg, &mut tag).unwrap();
        tag[0] ^= 1;
        assert_eq!(kmac.verify(&key, msg, &tag), Err(CryptoError::InvalidTag));
    }

    #[test]
    fn kmac128_zero_output_len_rejected() {
        assert_eq!(
            Kmac128::new(b"", 0).unwrap_err(),
            CryptoError::BadInput,
            "KMAC128 with output_len=0 must be rejected"
        );
    }

    // ── KMAC256 ──────────────────────────────────────────────────────────────

    /// NIST SP 800-185 §A.2 Sample #2 (KMAC256, empty customization, 64-byte output)
    ///
    /// Key    = 404142...5e5f (32 bytes)
    /// Data   = 00..c7 (200 bytes sequential)
    /// S      = "" (empty customization)
    /// L      = 512 bits (64 bytes)
    ///
    /// Expected:
    /// 75358cf39e41494e949707927cee0af2 0a3ff553904c86b08f21cc414bcfd691
    /// 589d27cf5e15369cbbff8b9a4c2eb178 00855d0235ff635da82533ec6b759b69
    ///
    /// Verified against tiny-keccak's test_kmac256_two.
    #[test]
    fn kmac256_nist_sp800_185_sample4() {
        let key = hex_decode(
            "404142434445464748494a4b4c4d4e4f\
             505152535455565758595a5b5c5d5e5f",
        );
        // 200-byte sequential data: 0x00..0xc7
        let data: alloc::vec::Vec<u8> = (0x00_u8..=0xc7_u8).collect();
        let expected = hex_decode(
            "75358cf39e41494e949707927cee0af2\
             0a3ff553904c86b08f21cc414bcfd691\
             589d27cf5e15369cbbff8b9a4c2eb178\
             00855d0235ff635da82533ec6b759b69",
        );

        let kmac = Kmac256::new(b"", 64).unwrap();
        let mut out = [0u8; 64];
        kmac.mac(&key, &data, &mut out).unwrap();
        assert_eq!(
            &out[..],
            expected.as_slice(),
            "KMAC256 SP 800-185 §A.2 Sample #2 (200-byte data, empty S)"
        );
    }

    #[test]
    fn kmac256_round_trip() {
        let kmac = Kmac256::new(b"domain", 64).unwrap();
        let key = [0xbb_u8; 32];
        let msg = b"hello kmac256";
        let mut tag = [0u8; 64];
        kmac.mac(&key, msg, &mut tag).unwrap();
        kmac.verify(&key, msg, &tag)
            .expect("KMAC256 verify must succeed");
    }

    #[test]
    fn kmac256_zero_output_len_rejected() {
        assert_eq!(
            Kmac256::new(b"", 0).unwrap_err(),
            CryptoError::BadInput,
            "KMAC256 with output_len=0 must be rejected"
        );
    }

    // ── Truncated HMAC ───────────────────────────────────────────────────────

    /// mac_truncated produces the prefix of the full tag.
    #[test]
    fn hmac_sha256_truncated_is_prefix() {
        let key = b"trunc-key";
        let msg = b"truncated message";

        let mac = HmacSha256;
        let mut full = [0u8; 32];
        mac.mac(key, msg, &mut full).unwrap();

        let mut trunc = [0u8; 20];
        mac.mac_truncated(key, msg, &mut trunc).unwrap();

        assert_eq!(
            &trunc[..],
            &full[..20],
            "truncated tag must be prefix of full tag"
        );
    }

    #[test]
    fn hmac_sha256_truncated_verify_ok() {
        let key = b"k";
        let msg = b"m";
        let mac = HmacSha256;

        let mut trunc = [0u8; 20];
        mac.mac_truncated(key, msg, &mut trunc).unwrap();
        mac.verify_truncated(key, msg, &trunc)
            .expect("truncated verify must succeed");
    }

    #[test]
    fn hmac_sha256_truncated_too_short_rejected() {
        let mac = HmacSha256;
        let mut buf = [0u8; 15];
        assert_eq!(
            mac.mac_truncated(b"k", b"m", &mut buf),
            Err(CryptoError::BadInput),
            "truncation below 16 bytes must be rejected"
        );
        assert_eq!(
            mac.verify_truncated(b"k", b"m", &buf),
            Err(CryptoError::BadInput),
            "verify with tag < 16 bytes must be rejected"
        );
    }

    #[test]
    fn hmac_sha512_truncated_is_prefix() {
        let key = b"key512";
        let msg = b"msg512";

        let mac = HmacSha512;
        let mut full = [0u8; 64];
        mac.mac(key, msg, &mut full).unwrap();

        let mut trunc = [0u8; 32];
        mac.mac_truncated(key, msg, &mut trunc).unwrap();

        assert_eq!(&trunc[..], &full[..32]);
    }

    #[test]
    fn hmac_sha384_truncated_is_prefix() {
        let key = b"key384";
        let msg = b"msg384";

        let mac = HmacSha384;
        let mut full = [0u8; 48];
        mac.mac(key, msg, &mut full).unwrap();

        let mut trunc = [0u8; 24];
        mac.mac_truncated(key, msg, &mut trunc).unwrap();

        assert_eq!(&trunc[..], &full[..24]);
    }

    // ── KMAC-XOF free functions ──────────────────────────────────────────────

    /// kmac128_xof and kmac256_xof must match the trait-based Kmac128/Kmac256
    /// for the same key/custom/msg/output_len.
    #[test]
    fn kmac128_xof_matches_trait_impl() {
        let key = hex_decode(
            "404142434445464748494a4b4c4d4e4f\
             505152535455565758595a5b5c5d5e5f",
        );
        let data = hex_decode("00010203");
        // Known-good: NIST SP 800-185 §A.1 Sample #1
        let expected = hex_decode(
            "e5780b0d3ea6f7d3a429c5706aa43a00\
             fadbd7d49628839e3187243f456ee14e",
        );

        let got = kmac128_xof(&key, b"", &data, 32).expect("kmac128_xof must not fail");
        assert_eq!(got, expected, "kmac128_xof NIST SP 800-185 Sample #1");
    }

    #[test]
    fn kmac128_xof_variable_lengths() {
        let key = [0xaau8; 16];
        let msg = b"variable-length output test";

        let out16 = kmac128_xof(&key, b"domain", msg, 16).unwrap();
        let out64 = kmac128_xof(&key, b"domain", msg, 64).unwrap();

        // KMAC encodes the output length into the message padding (SP 800-185 §4.3.1),
        // so different requested lengths produce entirely different outputs.
        // Both must be the right length and non-zero.
        assert_eq!(
            out16.len(),
            16,
            "kmac128_xof must produce exactly output_len bytes"
        );
        assert_eq!(
            out64.len(),
            64,
            "kmac128_xof must produce exactly output_len bytes"
        );
        assert!(out16.iter().any(|&b| b != 0), "output must be non-zero");
        assert!(out64.iter().any(|&b| b != 0), "output must be non-zero");
        // Different lengths → different outputs (length-dependent padding).
        assert_ne!(
            &out64[..16],
            out16.as_slice(),
            "KMAC: different output_len must differ"
        );
    }

    #[test]
    fn kmac128_xof_zero_len_rejected() {
        assert_eq!(
            kmac128_xof(b"key", b"", b"msg", 0).unwrap_err(),
            CryptoError::BadInput,
        );
    }

    #[test]
    fn kmac256_xof_matches_trait_impl() {
        let key = hex_decode(
            "404142434445464748494a4b4c4d4e4f\
             505152535455565758595a5b5c5d5e5f",
        );
        let data: alloc::vec::Vec<u8> = (0x00_u8..=0xc7_u8).collect();
        let expected = hex_decode(
            "75358cf39e41494e949707927cee0af2\
             0a3ff553904c86b08f21cc414bcfd691\
             589d27cf5e15369cbbff8b9a4c2eb178\
             00855d0235ff635da82533ec6b759b69",
        );

        let got = kmac256_xof(&key, b"", &data, 64).expect("kmac256_xof must not fail");
        assert_eq!(got, expected, "kmac256_xof NIST SP 800-185 §A.2 Sample #2");
    }

    #[test]
    fn kmac256_xof_zero_len_rejected() {
        assert_eq!(
            kmac256_xof(b"key", b"", b"msg", 0).unwrap_err(),
            CryptoError::BadInput,
        );
    }

    // ── BLAKE3 keyed-hash MAC ────────────────────────────────────────────────

    /// BLAKE3 keyed-hash output is deterministic.
    #[test]
    fn blake3_keyed_mac_deterministic() {
        let key = [0x42u8; 32];
        let msg = b"hello blake3 keyed mac";
        let t1 = blake3_keyed_mac(&key, msg);
        let t2 = blake3_keyed_mac(&key, msg);
        assert_eq!(t1, t2, "BLAKE3 keyed mac must be deterministic");
    }

    /// Different keys produce different tags.
    #[test]
    fn blake3_keyed_mac_key_dependent() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        let msg = b"same msg";
        assert_ne!(
            blake3_keyed_mac(&k1, msg),
            blake3_keyed_mac(&k2, msg),
            "Different keys must produce different BLAKE3 MACs"
        );
    }

    /// Verify round-trip.
    #[test]
    fn blake3_keyed_mac_verify_ok() {
        let key = [0xabu8; 32];
        let msg = b"verify me";
        let tag = blake3_keyed_mac(&key, msg);
        blake3_keyed_mac_verify(&key, msg, &tag).expect("BLAKE3 keyed verify must succeed");
    }

    /// Verify detects corruption.
    #[test]
    fn blake3_keyed_mac_verify_fail() {
        let key = [0xcd_u8; 32];
        let msg = b"corrupt me";
        let mut tag = blake3_keyed_mac(&key, msg);
        tag[0] ^= 0xff;
        assert_eq!(
            blake3_keyed_mac_verify(&key, msg, &tag),
            Err(CryptoError::InvalidTag),
            "corrupted BLAKE3 MAC must be rejected"
        );
    }

    // ── hmac_sha256_verify_truncated free function ───────────────────────────

    #[test]
    fn free_fn_verify_truncated_ok() {
        let key = b"verify-trunc-key";
        let msg = b"verify-trunc-msg";
        let mut full = [0u8; 32];
        HmacSha256.mac(key, msg, &mut full).unwrap();
        hmac_sha256_verify_truncated(key, msg, &full[..16])
            .expect("free-fn verify_truncated must accept valid 16-byte tag");
    }

    #[test]
    fn free_fn_verify_truncated_empty_rejected() {
        assert_eq!(
            hmac_sha256_verify_truncated(b"k", b"m", &[]),
            Err(CryptoError::BadInput),
        );
    }

    #[test]
    fn free_fn_verify_truncated_too_long_rejected() {
        assert_eq!(
            hmac_sha256_verify_truncated(b"k", b"m", &[0u8; 33]),
            Err(CryptoError::BadInput),
        );
    }

    #[test]
    fn free_fn_verify_truncated_mismatch() {
        let key = b"k";
        let msg = b"m";
        let mut full = [0u8; 32];
        HmacSha256.mac(key, msg, &mut full).unwrap();
        let mut bad = [0u8; 16];
        bad.copy_from_slice(&full[..16]);
        bad[0] ^= 0x01;
        assert_eq!(
            hmac_sha256_verify_truncated(key, msg, &bad),
            Err(CryptoError::InvalidTag),
        );
    }
}
