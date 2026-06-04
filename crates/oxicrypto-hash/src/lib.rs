#![forbid(unsafe_code)]
#![no_std]

//! Pure Rust hash function implementations for the OxiCrypto stack.
//!
//! Provides [`Hash`]-trait wrappers and [`StreamingHash`] adapters for:
//! - SHA-2: SHA-256, SHA-384, SHA-512, SHA-512/256 (FIPS 180-4)
//! - SHA-3: SHA3-256, SHA3-384, SHA3-512 (FIPS 202)
//! - BLAKE2: BLAKE2b-256, BLAKE2b-512, BLAKE2s-256 (RFC 7693)
//! - BLAKE3: standard, keyed-hash, key-derivation, XOF (blake3 spec)
//! - SHAKE128/256, cSHAKE128/256, TupleHash128/256 (NIST SP 800-185)
//! - BLAKE2b keyed-hash mode (RFC 7693 MAC mode)
//!
//! All streaming adapters implement [`StreamingHash`] via the generic
//! [`DigestStreamingAdapter`] wrapper which works with any `digest::Digest +
//! Default` type.

// `alloc` is required for `Vec`-returning functions such as `hash_to_vec`,
// `blake3_xof`, and `parallel_hash*_xof`. When the `no_std` feature is
// enabled, callers should prefer the alloc-free `hash_fixed` / `hash_to_array`
// paths (see feature documentation in Cargo.toml).
//
// This crate always links `alloc` because the sub-modules (parallelhash, xof,
// hash_builder) depend on it internally. The `no_std` feature flag serves as an
// API-guidance signal rather than a link-time exclusion: it documents which
// methods are suitable for embedded / alloc-free callers.
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod hash_builder;
mod parallelhash;
mod xof;
pub use hash_builder::{DynStreamingHash, HashAlgorithm, HashBuilder, StreamingHashBuilder};
pub use parallelhash::{
    parallel_hash128, parallel_hash128_xof, parallel_hash256, parallel_hash256_xof,
    ParallelHash128, ParallelHash256,
};
pub use xof::{
    blake2b_keyed, cshake128, cshake256, shake128, shake128_start, shake256, shake256_start,
    tuple_hash128, tuple_hash256, Blake2bKeyed, Shake128Reader, Shake256Reader,
};

#[cfg(feature = "std")]
pub use xof::{hash_file_blake3, hash_file_sha256, hash_file_sha512};

use alloc::vec::Vec;

use digest::Digest;
use oxicrypto_core::{CryptoError, Hash, StreamingHash};

// ── Generic streaming adapter ────────────────────────────────────────────────

/// Generic streaming adapter wrapping any `digest::Digest + Default` type.
///
/// Implements [`StreamingHash`] for all `digest 0.11`-compatible hash
/// functions (SHA-2, SHA-3, BLAKE2). BLAKE3 uses a separate impl.
pub struct DigestStreamingAdapter<D: Digest + Default> {
    inner: D,
}

impl<D: Digest + Default> DigestStreamingAdapter<D> {
    /// Create a new adapter in the initial (empty) state.
    pub fn new() -> Self {
        Self {
            inner: D::default(),
        }
    }
}

impl<D: Digest + Default> Default for DigestStreamingAdapter<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest + Default + Clone> Clone for DigestStreamingAdapter<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: Digest + Default + Send> StreamingHash for DigestStreamingAdapter<D> {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        let result = Digest::finalize(self.inner);
        if out.len() < result.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        out[..result.len()].copy_from_slice(&result);
        Ok(())
    }

    fn reset(&mut self) {
        self.inner = D::default();
    }
}

// ── SHA-2 one-shot ───────────────────────────────────────────────────────────

/// SHA-256 hash function (32-byte output, FIPS 180-4 §6.2).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256;

/// SHA-384 hash function (48-byte output, FIPS 180-4 §6.5).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha384;

/// SHA-512 hash function (64-byte output, FIPS 180-4 §6.4).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512;

/// SHA-512/256 truncated hash function (32-byte output, FIPS 180-4 §6.7).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512_256;

impl Hash for Sha256 {
    fn name(&self) -> &'static str {
        "SHA-256"
    }
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = sha2::Sha256::digest(msg);
        out[..32].copy_from_slice(&digest);
        Ok(())
    }
}

impl Hash for Sha384 {
    fn name(&self) -> &'static str {
        "SHA-384"
    }
    fn output_len(&self) -> usize {
        48
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 48 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = sha2::Sha384::digest(msg);
        out[..48].copy_from_slice(&digest);
        Ok(())
    }
}

impl Hash for Sha512 {
    fn name(&self) -> &'static str {
        "SHA-512"
    }
    fn output_len(&self) -> usize {
        64
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = sha2::Sha512::digest(msg);
        out[..64].copy_from_slice(&digest);
        Ok(())
    }
}

impl Hash for Sha512_256 {
    fn name(&self) -> &'static str {
        "SHA-512/256"
    }
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = sha2::Sha512_256::digest(msg);
        out[..32].copy_from_slice(&digest);
        Ok(())
    }
}

// ── SHA-2 digest length constants ────────────────────────────────────────────

impl Sha256 {
    /// Byte length of the SHA-256 digest output.
    pub const DIGEST_LEN: usize = 32;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 32;
    /// SHA-256 block size in bytes (FIPS 180-4).
    pub const BLOCK_SIZE: usize = 64;
}

impl Sha384 {
    /// Byte length of the SHA-384 digest output.
    pub const DIGEST_LEN: usize = 48;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 48;
    /// SHA-384 block size in bytes (FIPS 180-4).
    pub const BLOCK_SIZE: usize = 128;
}

impl Sha512 {
    /// Byte length of the SHA-512 digest output.
    pub const DIGEST_LEN: usize = 64;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 64;
    /// SHA-512 block size in bytes (FIPS 180-4).
    pub const BLOCK_SIZE: usize = 128;
}

impl Sha512_256 {
    /// Byte length of the SHA-512/256 digest output.
    pub const DIGEST_LEN: usize = 32;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 32;
    /// SHA-512/256 block size in bytes (FIPS 180-4).
    pub const BLOCK_SIZE: usize = 128;
}

// ── SHA-2 streaming ──────────────────────────────────────────────────────────

/// Streaming SHA-256 hasher.
pub type Sha256Streaming = DigestStreamingAdapter<sha2::Sha256>;
/// Streaming SHA-384 hasher.
pub type Sha384Streaming = DigestStreamingAdapter<sha2::Sha384>;
/// Streaming SHA-512 hasher.
pub type Sha512Streaming = DigestStreamingAdapter<sha2::Sha512>;
/// Streaming SHA-512/256 hasher.
pub type Sha512_256Streaming = DigestStreamingAdapter<sha2::Sha512_256>;

// ── SHA-3 one-shot ───────────────────────────────────────────────────────────

/// SHA3-256 hash function (32-byte output, FIPS 202).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha3_256;

/// SHA3-384 hash function (48-byte output, FIPS 202).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha3_384;

/// SHA3-512 hash function (64-byte output, FIPS 202).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha3_512;

impl Hash for Sha3_256 {
    fn name(&self) -> &'static str {
        "SHA3-256"
    }
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = sha3::Sha3_256::digest(msg);
        out[..32].copy_from_slice(&digest);
        Ok(())
    }
}

impl Hash for Sha3_384 {
    fn name(&self) -> &'static str {
        "SHA3-384"
    }
    fn output_len(&self) -> usize {
        48
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 48 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = sha3::Sha3_384::digest(msg);
        out[..48].copy_from_slice(&digest);
        Ok(())
    }
}

impl Hash for Sha3_512 {
    fn name(&self) -> &'static str {
        "SHA3-512"
    }
    fn output_len(&self) -> usize {
        64
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = sha3::Sha3_512::digest(msg);
        out[..64].copy_from_slice(&digest);
        Ok(())
    }
}

// ── SHA-3 digest length constants ────────────────────────────────────────────

impl Sha3_256 {
    /// Byte length of the SHA3-256 digest output.
    pub const DIGEST_LEN: usize = 32;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 32;
    /// SHA3-256 block (rate) size in bytes (FIPS 202).
    pub const BLOCK_SIZE: usize = 136;
}

impl Sha3_384 {
    /// Byte length of the SHA3-384 digest output.
    pub const DIGEST_LEN: usize = 48;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 48;
    /// SHA3-384 block (rate) size in bytes (FIPS 202).
    pub const BLOCK_SIZE: usize = 104;
}

impl Sha3_512 {
    /// Byte length of the SHA3-512 digest output.
    pub const DIGEST_LEN: usize = 64;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 64;
    /// SHA3-512 block (rate) size in bytes (FIPS 202).
    pub const BLOCK_SIZE: usize = 72;
}

// ── SHA-3 streaming ──────────────────────────────────────────────────────────

/// Streaming SHA3-256 hasher.
pub type Sha3_256Streaming = DigestStreamingAdapter<sha3::Sha3_256>;
/// Streaming SHA3-384 hasher.
pub type Sha3_384Streaming = DigestStreamingAdapter<sha3::Sha3_384>;
/// Streaming SHA3-512 hasher.
pub type Sha3_512Streaming = DigestStreamingAdapter<sha3::Sha3_512>;

// ── BLAKE2 one-shot ──────────────────────────────────────────────────────────

/// BLAKE2b-256 hash function (32-byte output, RFC 7693).
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake2b256;

/// BLAKE2b-512 hash function (64-byte output, RFC 7693).
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake2b512;

/// BLAKE2s-256 hash function (32-byte output, RFC 7693).
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake2s256;

impl Hash for Blake2b256 {
    fn name(&self) -> &'static str {
        "BLAKE2b-256"
    }
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let result = blake2::Blake2b256::digest(msg);
        out[..32].copy_from_slice(&result);
        Ok(())
    }
}

impl Hash for Blake2b512 {
    fn name(&self) -> &'static str {
        "BLAKE2b-512"
    }
    fn output_len(&self) -> usize {
        64
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        let result = blake2::Blake2b512::digest(msg);
        out[..64].copy_from_slice(&result);
        Ok(())
    }
}

impl Hash for Blake2s256 {
    fn name(&self) -> &'static str {
        "BLAKE2s-256"
    }
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let result = blake2::Blake2s256::digest(msg);
        out[..32].copy_from_slice(&result);
        Ok(())
    }
}

// ── BLAKE2 digest length constants ───────────────────────────────────────────

impl Blake2b256 {
    /// Byte length of the BLAKE2b-256 digest output.
    pub const DIGEST_LEN: usize = 32;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 32;
    /// BLAKE2b block size in bytes (RFC 7693).
    pub const BLOCK_SIZE: usize = 128;
}

impl Blake2b512 {
    /// Byte length of the BLAKE2b-512 digest output.
    pub const DIGEST_LEN: usize = 64;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 64;
    /// BLAKE2b block size in bytes (RFC 7693).
    pub const BLOCK_SIZE: usize = 128;
}

impl Blake2s256 {
    /// Byte length of the BLAKE2s-256 digest output.
    pub const DIGEST_LEN: usize = 32;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 32;
    /// BLAKE2s block size in bytes (RFC 7693).
    pub const BLOCK_SIZE: usize = 64;
}

// ── BLAKE2 streaming ─────────────────────────────────────────────────────────

/// Streaming BLAKE2b-256 hasher (32-byte output).
pub type Blake2b256Streaming = DigestStreamingAdapter<blake2::Blake2b256>;
/// Streaming BLAKE2b-512 hasher (64-byte output).
pub type Blake2b512Streaming = DigestStreamingAdapter<blake2::Blake2b512>;
/// Streaming BLAKE2s-256 hasher (32-byte output).
pub type Blake2s256Streaming = DigestStreamingAdapter<blake2::Blake2s256>;

// ── BLAKE3 one-shot ───────────────────────────────────────────────────────────

/// BLAKE3 hash function (32-byte output by default).
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake3;

impl Hash for Blake3 {
    fn name(&self) -> &'static str {
        "BLAKE3"
    }
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let digest = blake3::hash(msg);
        out[..32].copy_from_slice(digest.as_bytes());
        Ok(())
    }
}

impl Blake3 {
    /// Byte length of the BLAKE3 default digest output.
    pub const DIGEST_LEN: usize = 32;
    /// Output length in bytes (alias for `DIGEST_LEN`; use for generic const contexts).
    pub const OUTPUT_LEN: usize = 32;
    /// BLAKE3 block size in bytes.
    pub const BLOCK_SIZE: usize = 64;
}

// ── BLAKE3 streaming ─────────────────────────────────────────────────────────

/// Streaming BLAKE3 hasher (32-byte output).
///
/// Uses `blake3::Hasher` directly since blake3 has its own incremental API.
pub struct Blake3Streaming {
    inner: blake3::Hasher,
}

impl Blake3Streaming {
    /// Create a new BLAKE3 streaming hasher.
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }
}

impl Default for Blake3Streaming {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Blake3Streaming {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl StreamingHash for Blake3Streaming {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let result = self.inner.finalize();
        out[..32].copy_from_slice(result.as_bytes());
        Ok(())
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

// ── std::io::Write for streaming hashers ─────────────────────────────────────

/// Implement `std::io::Write` for [`DigestStreamingAdapter`] so that streaming
/// hashers can be used as sinks in generic I/O pipelines.
#[cfg(feature = "std")]
impl<D: Digest + Default + Send> std::io::Write for DigestStreamingAdapter<D> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Implement `std::io::Write` for [`Blake3Streaming`] so that it can be used
/// as a sink in generic I/O pipelines.
#[cfg(feature = "std")]
impl std::io::Write for Blake3Streaming {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── Hex-digest convenience functions ─────────────────────────────────────────

/// Hash `msg` with SHA-256 and return a lowercase hex string.
///
/// This function requires the `std` feature because it allocates a `String`.
#[cfg(feature = "std")]
pub fn sha256_hex(msg: &[u8]) -> std::string::String {
    let digest = sha2::Sha256::digest(msg);
    bytes_to_hex(digest.as_ref())
}

/// Hash `msg` with SHA-384 and return a lowercase hex string.
#[cfg(feature = "std")]
pub fn sha384_hex(msg: &[u8]) -> std::string::String {
    let digest = sha2::Sha384::digest(msg);
    bytes_to_hex(digest.as_ref())
}

/// Hash `msg` with SHA-512 and return a lowercase hex string.
#[cfg(feature = "std")]
pub fn sha512_hex(msg: &[u8]) -> std::string::String {
    let digest = sha2::Sha512::digest(msg);
    bytes_to_hex(digest.as_ref())
}

/// Hash `msg` with SHA3-256 and return a lowercase hex string.
#[cfg(feature = "std")]
pub fn sha3_256_hex(msg: &[u8]) -> std::string::String {
    let digest = sha3::Sha3_256::digest(msg);
    bytes_to_hex(digest.as_ref())
}

/// Hash `msg` with BLAKE3 and return a lowercase hex string.
#[cfg(feature = "std")]
pub fn blake3_hex(msg: &[u8]) -> std::string::String {
    let digest = blake3::hash(msg);
    bytes_to_hex(digest.as_bytes())
}

/// Convert a byte slice to a lowercase hexadecimal string.
#[cfg(feature = "std")]
fn bytes_to_hex(bytes: &[u8]) -> std::string::String {
    bytes.iter().fold(
        std::string::String::with_capacity(bytes.len() * 2),
        |mut s, b| {
            let _ = std::fmt::write(&mut s, format_args!("{b:02x}"));
            s
        },
    )
}

// ── BLAKE3 keyed-hash mode ───────────────────────────────────────────────────

/// BLAKE3 keyed-hash (MAC-like): deterministic 32-byte output under a 32-byte key.
///
/// Produces a unique output for each (key, message) pair. Keys are 32 bytes
/// and must be kept secret for MAC use cases.
pub struct Blake3Keyed {
    key: [u8; 32],
}

impl Blake3Keyed {
    /// Create a keyed hasher with the given 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Hash `msg` under this key; returns 32 bytes.
    pub fn hash(&self, msg: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.key, msg).as_bytes()
    }
}

/// Hash `msg` under `key` with BLAKE3 keyed-hash mode; returns 32 bytes.
///
/// Convenience free function — equivalent to `Blake3Keyed::new(key).hash(msg)`.
pub fn blake3_keyed_hash(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, msg).as_bytes()
}

// ── BLAKE3 key-derivation mode ───────────────────────────────────────────────

/// Derive a 32-byte key using BLAKE3 key-derivation mode.
///
/// `context` must be a globally unique, hardcoded string describing the
/// purpose (e.g. `"MyApp 2024-01 file encryption key"`).  Key material
/// may be any length, including zero.
pub fn blake3_derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key_material)
}

// ── Alloc-free fixed-array hash helpers ────────────────────────────────────
//
// These inherent methods compute a hash and write into a stack-allocated
// `[u8; N]` array without any heap allocation. They are the preferred API
// when the `no_std` feature is enabled (or in any context where `alloc` is
// undesirable).
//
// All concrete hash types implement `hash_fixed<N>()` which is equivalent
// to `Hash::hash_to_array::<N>()` from `oxicrypto-core` but surfaced here
// as an ergonomic shorthand directly on the type.
//
// Usage (alloc-free):
//
// ```rust
// let digest: [u8; 32] = Sha256.hash_fixed(b"hello");
// let digest: [u8; 64] = Sha512.hash_fixed(b"hello");
// let digest: [u8; 32] = Blake3.hash_fixed(b"hello");
// ```
//
// The `no_std` feature flag makes this distinction visible at the type level:
// with `no_std` enabled, `Hash::hash_to_vec` (which requires `alloc`) is
// documented as unavailable and callers should use `hash_fixed` or
// `Hash::hash_to_array` instead.

impl Sha256 {
    /// Hash `msg` and return the 32-byte SHA-256 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    ///
    /// # `no_std` note
    ///
    /// When the `no_std` feature is enabled, prefer this method over
    /// `hash_to_vec`, which requires heap allocation.
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(msg).into()
    }
}

impl Sha384 {
    /// Hash `msg` and return the 48-byte SHA-384 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 48] {
        sha2::Sha384::digest(msg).into()
    }
}

impl Sha512 {
    /// Hash `msg` and return the 64-byte SHA-512 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 64] {
        sha2::Sha512::digest(msg).into()
    }
}

impl Sha512_256 {
    /// Hash `msg` and return the 32-byte SHA-512/256 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 32] {
        sha2::Sha512_256::digest(msg).into()
    }
}

impl Sha3_256 {
    /// Hash `msg` and return the 32-byte SHA3-256 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 32] {
        sha3::Sha3_256::digest(msg).into()
    }
}

impl Sha3_384 {
    /// Hash `msg` and return the 48-byte SHA3-384 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 48] {
        sha3::Sha3_384::digest(msg).into()
    }
}

impl Sha3_512 {
    /// Hash `msg` and return the 64-byte SHA3-512 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 64] {
        sha3::Sha3_512::digest(msg).into()
    }
}

impl Blake2b256 {
    /// Hash `msg` and return the 32-byte BLAKE2b-256 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 32] {
        blake2::Blake2b256::digest(msg).into()
    }
}

impl Blake2b512 {
    /// Hash `msg` and return the 64-byte BLAKE2b-512 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 64] {
        blake2::Blake2b512::digest(msg).into()
    }
}

impl Blake2s256 {
    /// Hash `msg` and return the 32-byte BLAKE2s-256 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 32] {
        blake2::Blake2s256::digest(msg).into()
    }
}

impl Blake3 {
    /// Hash `msg` and return the 32-byte BLAKE3 digest as a fixed-size array.
    ///
    /// Alloc-free alternative to [`Hash::hash_to_vec`].
    ///
    /// # `no_std` note
    ///
    /// When the `no_std` feature is enabled, this method (along with
    /// `blake3_keyed_hash` and `blake3_derive_key`) is the preferred API
    /// since it avoids heap allocation entirely.
    #[inline]
    #[must_use]
    pub fn hash_fixed(&self, msg: &[u8]) -> [u8; 32] {
        *blake3::hash(msg).as_bytes()
    }
}

// ── BLAKE3 XOF (extendable output) ───────────────────────────────────────────

/// Hash `msg` with BLAKE3 and return `output_len` bytes.
///
/// The first 32 bytes are identical to the standard BLAKE3 hash of `msg`.
/// Requesting more than 32 bytes extends the output using BLAKE3's XOF
/// (extendable output function) mode.
///
/// # `no_std` note
///
/// This function allocates a `Vec<u8>`. When the `no_std` feature is enabled,
/// use [`Blake3::hash_fixed`] for a 32-byte alloc-free alternative, or write
/// the XOF output directly into a caller-provided `&mut [u8]` using
/// `blake3::Hasher::finalize_xof().fill()`.
pub fn blake3_xof(msg: &[u8], output_len: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; output_len];
    let mut reader = blake3::Hasher::new().update(msg).finalize_xof();
    reader.fill(&mut out);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap_or_else(|e| panic!("invalid hex string {s:?}: {e}"))
    }

    // ── SHA-256 ──────────────────────────────────────────────────────────────

    #[test]
    fn sha256_empty() {
        let hasher = Sha256;
        let result = hasher.hash_to_vec(b"").unwrap();
        let expected =
            hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(result, expected, "SHA-256 of empty string mismatch");
    }

    #[test]
    fn sha256_abc() {
        let hasher = Sha256;
        let result = hasher.hash_to_vec(b"abc").unwrap();
        // NIST FIPS 180-4 test vector: SHA-256("abc")
        let expected =
            hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(result, expected, "SHA-256 of 'abc' mismatch");
    }

    #[test]
    fn sha384_abc() {
        let hasher = Sha384;
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn sha512_abc() {
        let hasher = Sha512;
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn sha3_256_output_len() {
        let hasher = Sha3_256;
        assert_eq!(hasher.output_len(), 32);
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn sha3_384_output_len() {
        let hasher = Sha3_384;
        assert_eq!(hasher.output_len(), 48);
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn sha3_512_output_len() {
        let hasher = Sha3_512;
        assert_eq!(hasher.output_len(), 64);
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn blake3_abc() {
        let hasher = Blake3;
        let result = hasher.hash_to_vec(b"abc").unwrap();
        // Official BLAKE3 test vector for "abc":
        // https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
        let expected =
            hex_decode("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
        assert_eq!(result, expected, "BLAKE3 of 'abc' mismatch");
    }

    #[test]
    fn buffer_too_small_error() {
        let hasher = Sha256;
        let mut out = [0u8; 16];
        let err = hasher.hash(b"test", &mut out).unwrap_err();
        assert_eq!(err, CryptoError::BufferTooSmall);
    }

    // ── Streaming: SHA-256 equivalence ───────────────────────────────────────

    #[test]
    fn sha256_streaming_hello_world() {
        // Streaming "hello" + " world" must equal one-shot "hello world"
        let one_shot = Sha256.hash_to_vec(b"hello world").unwrap();

        let mut streamer = Sha256Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::update(&mut streamer, b" world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), one_shot.as_slice());
    }

    #[test]
    fn sha256_streaming_one_byte_chunks() {
        // Feed "abc" one byte at a time; must equal one-shot SHA-256("abc")
        let one_shot = Sha256.hash_to_vec(b"abc").unwrap();

        let mut streamer = Sha256Streaming::new();
        for byte in b"abc" {
            StreamingHash::update(&mut streamer, core::slice::from_ref(byte));
        }
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), one_shot.as_slice());
    }

    #[test]
    fn sha256_streaming_reset() {
        // After reset, streaming should produce a fresh hash
        let expected = Sha256.hash_to_vec(b"world").unwrap();

        let mut streamer = Sha256Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::reset(&mut streamer);
        StreamingHash::update(&mut streamer, b"world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), expected.as_slice());
    }

    #[test]
    fn sha256_streaming_buffer_too_small() {
        let mut streamer = Sha256Streaming::new();
        StreamingHash::update(&mut streamer, b"test");
        let mut buf = [0u8; 16];
        let err = StreamingHash::finalize(streamer, &mut buf).unwrap_err();
        assert_eq!(err, CryptoError::BufferTooSmall);
    }

    // ── Streaming: BLAKE3 ────────────────────────────────────────────────────

    #[test]
    fn blake3_streaming_equivalence() {
        let one_shot = Blake3.hash_to_vec(b"hello world").unwrap();

        let mut streamer = Blake3Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::update(&mut streamer, b" world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), one_shot.as_slice());
    }

    #[test]
    fn blake3_streaming_reset() {
        let expected = Blake3.hash_to_vec(b"world").unwrap();

        let mut streamer = Blake3Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::reset(&mut streamer);
        StreamingHash::update(&mut streamer, b"world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), expected.as_slice());
    }

    // ── BLAKE2b-256 ──────────────────────────────────────────────────────────

    #[test]
    fn blake2b256_output_len() {
        let hasher = Blake2b256;
        assert_eq!(hasher.output_len(), 32);
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn blake2b256_empty_nonzero() {
        // BLAKE2b("")  -- just verify non-zero output of correct length
        let result = Blake2b256.hash_to_vec(b"").unwrap();
        assert_eq!(result.len(), 32);
        assert!(
            result.iter().any(|&b| b != 0),
            "BLAKE2b-256 of empty should be non-zero"
        );
    }

    #[test]
    fn blake2b256_streaming_equivalence() {
        let one_shot = Blake2b256.hash_to_vec(b"hello world").unwrap();

        let mut streamer = Blake2b256Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::update(&mut streamer, b" world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), one_shot.as_slice());
    }

    // ── BLAKE2b-512 ──────────────────────────────────────────────────────────

    #[test]
    fn blake2b512_output_len() {
        let hasher = Blake2b512;
        assert_eq!(hasher.output_len(), 64);
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn blake2b512_streaming_equivalence() {
        let one_shot = Blake2b512.hash_to_vec(b"hello world").unwrap();

        let mut streamer = Blake2b512Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::update(&mut streamer, b" world");
        let mut buf = [0u8; 64];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), one_shot.as_slice());
    }

    // ── BLAKE2s-256 ──────────────────────────────────────────────────────────

    #[test]
    fn blake2s256_output_len() {
        let hasher = Blake2s256;
        assert_eq!(hasher.output_len(), 32);
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn blake2s256_streaming_equivalence() {
        let one_shot = Blake2s256.hash_to_vec(b"hello world").unwrap();

        let mut streamer = Blake2s256Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::update(&mut streamer, b" world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), one_shot.as_slice());
    }

    // ── SHA-512/256 ──────────────────────────────────────────────────────────

    #[test]
    fn sha512_256_output_len() {
        let hasher = Sha512_256;
        assert_eq!(hasher.output_len(), 32);
        let result = hasher.hash_to_vec(b"abc").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn sha512_256_known_vector() {
        // FIPS 180-4 known value: SHA-512/256("abc")
        let result = Sha512_256.hash_to_vec(b"abc").unwrap();
        let expected =
            hex_decode("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
        assert_eq!(result, expected, "SHA-512/256 of 'abc' mismatch");
    }

    #[test]
    fn sha512_256_streaming_equivalence() {
        let one_shot = Sha512_256.hash_to_vec(b"hello world").unwrap();

        let mut streamer = Sha512_256Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        StreamingHash::update(&mut streamer, b" world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).unwrap();

        assert_eq!(buf.as_ref(), one_shot.as_slice());
    }

    // ── Blake3Keyed ──────────────────────────────────────────────────────────

    #[test]
    fn blake3_keyed_different_keys() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let msg = b"same message";

        let out1 = Blake3Keyed::new(key1).hash(msg);
        let out2 = Blake3Keyed::new(key2).hash(msg);

        assert_ne!(out1, out2, "Different keys must produce different outputs");
    }

    #[test]
    fn blake3_keyed_different_messages() {
        let key = [42u8; 32];
        let out1 = Blake3Keyed::new(key).hash(b"message1");
        let out2 = Blake3Keyed::new(key).hash(b"message2");

        assert_ne!(
            out1, out2,
            "Different messages must produce different outputs"
        );
    }

    #[test]
    fn blake3_keyed_deterministic() {
        let key = [7u8; 32];
        let msg = b"deterministic";
        let out1 = Blake3Keyed::new(key).hash(msg);
        let out2 = blake3_keyed_hash(&key, msg);

        assert_eq!(out1, out2, "Method and free function must agree");
    }

    // ── blake3_derive_key ────────────────────────────────────────────────────

    #[test]
    fn blake3_derive_key_different_contexts() {
        let material = b"shared key material";
        let out1 = blake3_derive_key("context A", material);
        let out2 = blake3_derive_key("context B", material);

        assert_ne!(
            out1, out2,
            "Different contexts must produce different derived keys"
        );
    }

    #[test]
    fn blake3_derive_key_deterministic() {
        let material = b"deterministic material";
        let out1 = blake3_derive_key("test context", material);
        let out2 = blake3_derive_key("test context", material);

        assert_eq!(out1, out2, "derive_key must be deterministic");
    }

    #[test]
    fn blake3_derive_key_output_len() {
        let out = blake3_derive_key("oxicrypto test", b"material");
        assert_eq!(out.len(), 32);
    }

    // ── blake3_xof ───────────────────────────────────────────────────────────

    #[test]
    fn blake3_xof_64_bytes() {
        let out = blake3_xof(b"hello", 64);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn blake3_xof_first_32_match_standard_hash() {
        let msg = b"xof test";
        let standard = Blake3.hash_to_vec(msg).unwrap();
        let extended = blake3_xof(msg, 64);

        assert_eq!(
            &extended[..32],
            standard.as_slice(),
            "First 32 bytes of XOF must match standard BLAKE3 hash"
        );
    }

    #[test]
    fn blake3_xof_prefix_consistency() {
        let msg = b"prefix test";
        let out64 = blake3_xof(msg, 64);
        let out128 = blake3_xof(msg, 128);

        assert_eq!(
            &out128[..64],
            out64.as_slice(),
            "128-byte XOF must be prefixed by 64-byte XOF"
        );
    }

    #[test]
    fn blake3_xof_zero_len() {
        let out = blake3_xof(b"anything", 0);
        assert!(out.is_empty());
    }

    // ── OUTPUT_LEN inherent constants (WI-A: const-assoc-consts) ────────────

    #[test]
    fn test_output_len_consts() {
        assert_eq!(Sha256::OUTPUT_LEN, 32);
        assert_eq!(Sha384::OUTPUT_LEN, 48);
        assert_eq!(Sha512::OUTPUT_LEN, 64);
        assert_eq!(Sha512_256::OUTPUT_LEN, 32);
        assert_eq!(Sha3_256::OUTPUT_LEN, 32);
        assert_eq!(Sha3_384::OUTPUT_LEN, 48);
        assert_eq!(Sha3_512::OUTPUT_LEN, 64);
        assert_eq!(Blake2b256::OUTPUT_LEN, 32);
        assert_eq!(Blake2b512::OUTPUT_LEN, 64);
        assert_eq!(Blake2s256::OUTPUT_LEN, 32);
        assert_eq!(Blake3::OUTPUT_LEN, 32);
    }

    #[test]
    fn test_output_len_matches_runtime_output_len() {
        assert_eq!(Sha256::OUTPUT_LEN, Sha256.output_len());
        assert_eq!(Sha384::OUTPUT_LEN, Sha384.output_len());
        assert_eq!(Sha512::OUTPUT_LEN, Sha512.output_len());
        assert_eq!(Sha512_256::OUTPUT_LEN, Sha512_256.output_len());
        assert_eq!(Sha3_256::OUTPUT_LEN, Sha3_256.output_len());
        assert_eq!(Sha3_384::OUTPUT_LEN, Sha3_384.output_len());
        assert_eq!(Sha3_512::OUTPUT_LEN, Sha3_512.output_len());
        assert_eq!(Blake2b256::OUTPUT_LEN, Blake2b256.output_len());
        assert_eq!(Blake2b512::OUTPUT_LEN, Blake2b512.output_len());
        assert_eq!(Blake2s256::OUTPUT_LEN, Blake2s256.output_len());
        assert_eq!(Blake3::OUTPUT_LEN, Blake3.output_len());
    }

    // ── DIGEST_LEN / BLOCK_SIZE constants ────────────────────────────────────

    #[test]
    fn sha256_digest_len_constant() {
        assert_eq!(Sha256::DIGEST_LEN, 32);
        assert_eq!(Sha256::BLOCK_SIZE, 64);
    }

    #[test]
    fn sha384_digest_len_constant() {
        assert_eq!(Sha384::DIGEST_LEN, 48);
        assert_eq!(Sha384::BLOCK_SIZE, 128);
    }

    #[test]
    fn sha512_digest_len_constant() {
        assert_eq!(Sha512::DIGEST_LEN, 64);
        assert_eq!(Sha512::BLOCK_SIZE, 128);
    }

    #[test]
    fn sha3_256_digest_len_constant() {
        assert_eq!(Sha3_256::DIGEST_LEN, 32);
    }

    #[test]
    fn blake3_digest_len_constant() {
        assert_eq!(Blake3::DIGEST_LEN, 32);
        assert_eq!(Blake3::BLOCK_SIZE, 64);
    }

    #[test]
    fn blake2b256_digest_len_constant() {
        assert_eq!(Blake2b256::DIGEST_LEN, 32);
        assert_eq!(Blake2b256::BLOCK_SIZE, 128);
    }

    #[test]
    fn blake2b512_digest_len_constant() {
        assert_eq!(Blake2b512::DIGEST_LEN, 64);
        assert_eq!(Blake2b512::BLOCK_SIZE, 128);
    }

    #[test]
    fn blake2s256_digest_len_constant() {
        assert_eq!(Blake2s256::DIGEST_LEN, 32);
        assert_eq!(Blake2s256::BLOCK_SIZE, 64);
    }

    // ── Constants match runtime output_len ───────────────────────────────────

    #[test]
    fn constants_match_runtime_output_len() {
        assert_eq!(Sha256::DIGEST_LEN, Sha256.output_len());
        assert_eq!(Sha384::DIGEST_LEN, Sha384.output_len());
        assert_eq!(Sha512::DIGEST_LEN, Sha512.output_len());
        assert_eq!(Blake3::DIGEST_LEN, Blake3.output_len());
        assert_eq!(Blake2b256::DIGEST_LEN, Blake2b256.output_len());
        assert_eq!(Blake2b512::DIGEST_LEN, Blake2b512.output_len());
        assert_eq!(Blake2s256::DIGEST_LEN, Blake2s256.output_len());
    }

    // ── Clone for streaming types ─────────────────────────────────────────────

    #[test]
    fn sha256_streaming_clone_independent() {
        let mut streamer = Sha256Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        let mut cloned = streamer.clone();
        // Feed different data to original vs clone
        StreamingHash::update(&mut streamer, b" world");
        StreamingHash::update(&mut cloned, b" clone");

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf1).expect("finalize original");
        StreamingHash::finalize(cloned, &mut buf2).expect("finalize clone");

        // Different suffixes → different digests
        assert_ne!(
            buf1, buf2,
            "cloned streamer with different data must differ"
        );
    }

    #[test]
    fn blake3_streaming_clone_independent() {
        let mut streamer = Blake3Streaming::new();
        StreamingHash::update(&mut streamer, b"hello");
        let mut cloned = streamer.clone();
        StreamingHash::update(&mut streamer, b" a");
        StreamingHash::update(&mut cloned, b" b");

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf1).expect("finalize original");
        StreamingHash::finalize(cloned, &mut buf2).expect("finalize clone");

        assert_ne!(
            buf1, buf2,
            "cloned Blake3Streaming with different data must differ"
        );
    }

    // ── hex_digest functions ──────────────────────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hex = sha256_hex(b"");
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn sha256_hex_length() {
        let hex = sha256_hex(b"abc");
        assert_eq!(hex.len(), 64, "SHA-256 hex string must be 64 characters");
        // Must be lowercase hex
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn sha512_hex_length() {
        let hex = sha512_hex(b"abc");
        assert_eq!(hex.len(), 128, "SHA-512 hex string must be 128 characters");
    }

    #[cfg(feature = "std")]
    #[test]
    fn blake3_hex_known_vector() {
        // BLAKE3("abc") = 6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
        let hex = blake3_hex(b"abc");
        assert_eq!(
            hex,
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    // ── io::Write for streaming hashers ──────────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn sha256_streaming_io_write() {
        use std::io::Write;
        let mut streamer = Sha256Streaming::new();
        streamer.write_all(b"hello").expect("write_all hello");
        streamer.write_all(b" world").expect("write_all world");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).expect("finalize");

        let expected = Sha256.hash_to_vec(b"hello world").expect("one-shot");
        assert_eq!(
            &buf[..],
            expected.as_slice(),
            "io::Write result must match one-shot"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn blake3_streaming_io_write() {
        use std::io::Write;
        let mut streamer = Blake3Streaming::new();
        streamer.write_all(b"test data").expect("write_all");
        let mut buf = [0u8; 32];
        StreamingHash::finalize(streamer, &mut buf).expect("finalize");

        let expected = Blake3.hash_to_vec(b"test data").expect("one-shot");
        assert_eq!(
            &buf[..],
            expected.as_slice(),
            "io::Write result must match one-shot"
        );
    }

    // ── hash_fixed alloc-free path (no_std alternative to hash_to_vec) ────────
    //
    // These tests verify that the `hash_fixed` inherent methods (the alloc-free
    // alternative to `hash_to_vec`) produce identical digests to the `Hash`
    // trait path. When the `no_std` feature is enabled, callers use `hash_fixed`
    // or `Hash::hash_to_array` instead of `hash_to_vec`.

    #[test]
    fn sha256_hash_fixed_matches_hash_trait() {
        // SHA-256 fixed-array path must match the trait-based one-shot hash.
        let msg = b"alloc-free sha256 test";
        let fixed: [u8; 32] = Sha256.hash_fixed(msg);
        let via_trait = Sha256.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn sha384_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free sha384 test";
        let fixed: [u8; 48] = Sha384.hash_fixed(msg);
        let via_trait = Sha384.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn sha512_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free sha512 test";
        let fixed: [u8; 64] = Sha512.hash_fixed(msg);
        let via_trait = Sha512.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn sha512_256_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free sha512/256 test";
        let fixed: [u8; 32] = Sha512_256.hash_fixed(msg);
        let via_trait = Sha512_256.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn sha3_256_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free sha3-256 test";
        let fixed: [u8; 32] = Sha3_256.hash_fixed(msg);
        let via_trait = Sha3_256.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn sha3_384_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free sha3-384 test";
        let fixed: [u8; 48] = Sha3_384.hash_fixed(msg);
        let via_trait = Sha3_384.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn sha3_512_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free sha3-512 test";
        let fixed: [u8; 64] = Sha3_512.hash_fixed(msg);
        let via_trait = Sha3_512.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn blake2b256_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free blake2b256 test";
        let fixed: [u8; 32] = Blake2b256.hash_fixed(msg);
        let via_trait = Blake2b256.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn blake2b512_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free blake2b512 test";
        let fixed: [u8; 64] = Blake2b512.hash_fixed(msg);
        let via_trait = Blake2b512.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn blake2s256_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free blake2s256 test";
        let fixed: [u8; 32] = Blake2s256.hash_fixed(msg);
        let via_trait = Blake2s256.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn blake3_hash_fixed_matches_hash_trait() {
        let msg = b"alloc-free blake3 test";
        let fixed: [u8; 32] = Blake3.hash_fixed(msg);
        let via_trait = Blake3.hash_to_vec(msg).expect("hash_to_vec");
        assert_eq!(&fixed[..], via_trait.as_slice());
    }

    #[test]
    fn hash_fixed_known_vectors() {
        // Cross-verify hash_fixed against known-good RFC/NIST vectors.
        // SHA-256("abc") per FIPS 180-4 App B.1:
        let sha256_abc: [u8; 32] = Sha256.hash_fixed(b"abc");
        let expected_sha256 =
            hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_abc.as_ref(), expected_sha256.as_slice());
        // BLAKE3("abc") per official test vectors:
        let blake3_abc: [u8; 32] = Blake3.hash_fixed(b"abc");
        let expected_blake3 =
            hex_decode("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
        assert_eq!(blake3_abc.as_ref(), expected_blake3.as_slice());
    }

    #[test]
    fn hash_fixed_empty_input() {
        // SHA-256("") per FIPS 180-4:
        let fixed: [u8; 32] = Sha256.hash_fixed(b"");
        let expected =
            hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(fixed.as_ref(), expected.as_slice());
    }
}
