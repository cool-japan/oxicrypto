//! Generic HMAC adapter that accepts any [`StreamingHash`] implementation.
//!
//! This module provides [`StreamingHashHmac`] — a structurally correct HMAC
//! (RFC 2104) implementation that derives its inner hash from the
//! [`oxicrypto_core::StreamingHash`] trait rather than the `digest` crate's
//! `Digest` trait.  This allows callers to use any `oxicrypto-hash` streaming
//! hasher (SHA-256, SHA-512, BLAKE3, BLAKE2b-512, …) as the underlying PRF
//! without coupling `oxicrypto-mac` to the concrete hash crate.
//!
//! # Design
//!
//! HMAC requires two things beyond what `StreamingHash` exposes:
//!
//! 1. **Block size** — the internal compression block width (64 bytes for
//!    SHA-256, 128 bytes for SHA-512/SHA-384, 64 bytes for BLAKE3).
//! 2. **Fresh instances** — the RFC 2104 construction hashes three independent
//!    sub-messages (key-hash if key > block, inner, outer), so three separate
//!    hasher instances are needed in the general case.
//!
//! Both are supplied by the caller through the `block_size` parameter and a
//! factory closure `F: Fn() -> H`.  The resulting [`StreamingHashHmac`] is
//! independent of any specific hash algorithm.
//!
//! # HMAC construction (RFC 2104)
//!
//! ```text
//! K'  = K if |K| ≤ B, else H(K)
//! K'' = K' ‖ 0x00^(B - |K'|)        // zero-pad to B bytes
//! ipad = 0x36^B
//! opad = 0x5c^B
//! HMAC = H(K'' ⊕ opad ‖ H(K'' ⊕ ipad ‖ message))
//! ```
//!
//! where `B` = `block_size` and `H` = the streaming hasher created by the
//! factory.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use oxicrypto_core::{CryptoError, StreamingHash};
use subtle::ConstantTimeEq;

/// Generic HMAC over any [`StreamingHash`] implementation.
///
/// The type parameter `H` is the underlying hash; `F` is the factory that
/// creates fresh instances of `H`.  Both `H` and `F` must be `Send` to allow
/// the MAC to cross thread boundaries.
///
/// # Construction
///
/// Use [`StreamingHashHmac::new`] to provide a key, block size, and hash
/// factory.  The resulting value implements one-shot [`StreamingHashHmac::mac_oneshot`]
/// and incremental [`StreamingHashHmac::streaming_session`].
///
/// # Example
///
/// ```rust,ignore
/// use oxicrypto_hash::Sha256Streaming;
/// use oxicrypto_mac::hmac_streaming_hash::StreamingHashHmac;
///
/// let key = b"secret-key-for-hmac";
/// let msg = b"hello, world";
/// let mut tag = [0u8; 32];
/// let mut hmac = StreamingHashHmac::new(key, 64, || Sha256Streaming::new())?;
/// hmac.mac_oneshot(msg, &mut tag)?;
/// ```
pub struct StreamingHashHmac<H, F>
where
    H: StreamingHash,
    F: Fn() -> H + Send,
{
    /// Zero-padded, optionally pre-hashed key (length == block_size).
    padded_key: Vec<u8>,
    /// Hash block size (bytes).
    block_size: usize,
    /// Output length of the underlying hash (bytes).
    output_len: usize,
    /// Factory for creating fresh hasher instances.
    factory: F,
}

impl<H, F> StreamingHashHmac<H, F>
where
    H: StreamingHash,
    F: Fn() -> H + Send,
{
    /// Construct an HMAC instance with the given `key`, hash `block_size`, and
    /// `output_len` of the underlying `H`.
    ///
    /// - If `key.len() > block_size` the key is pre-hashed using a fresh
    ///   hasher from `factory`.
    /// - The padded key is zero-extended to exactly `block_size` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BadInput`] when `block_size` or `output_len` is
    /// zero, or when key pre-hashing would write into a zero-length buffer.
    pub fn new(
        key: &[u8],
        block_size: usize,
        output_len: usize,
        factory: F,
    ) -> Result<Self, CryptoError> {
        if block_size == 0 || output_len == 0 {
            return Err(CryptoError::BadInput);
        }

        // If key > block_size, hash it first (RFC 2104 §3).
        let effective_key: Vec<u8> = if key.len() > block_size {
            let mut hashed = vec![0u8; output_len];
            let mut h = (factory)();
            h.update(key);
            h.finalize(&mut hashed)?;
            hashed
        } else {
            key.to_vec()
        };

        // Zero-pad to exactly block_size.
        let mut padded_key = vec![0u8; block_size];
        let copy_len = effective_key.len().min(block_size);
        padded_key[..copy_len].copy_from_slice(&effective_key[..copy_len]);

        Ok(Self {
            padded_key,
            block_size,
            output_len,
            factory,
        })
    }

    /// Compute a one-shot HMAC tag over `msg`, writing into `out`.
    ///
    /// `out.len()` must be at least `self.output_len()`.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::BufferTooSmall`] if `out.len() < output_len`.
    pub fn mac_oneshot(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < self.output_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Pre-compute ipad/opad keys as contiguous byte slices.
        let ipad_key: Vec<u8> = self.padded_key.iter().map(|b| b ^ 0x36u8).collect();
        let opad_key: Vec<u8> = self.padded_key.iter().map(|b| b ^ 0x5cu8).collect();

        // inner = H(ipad_key || msg)
        let mut inner_tag = vec![0u8; self.output_len];
        {
            let mut h = (self.factory)();
            h.update(&ipad_key);
            h.update(msg);
            h.finalize(&mut inner_tag)?;
        }

        // outer = H(opad_key || inner)
        {
            let mut h = (self.factory)();
            h.update(&opad_key);
            h.update(&inner_tag);
            h.finalize(&mut out[..self.output_len])?;
        }

        Ok(())
    }

    /// The hash output length in bytes.
    pub fn output_len(&self) -> usize {
        self.output_len
    }

    /// The hash block size in bytes.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Constant-time verification: compute the HMAC and compare to `expected`.
    ///
    /// Returns `Ok(())` if they match, [`CryptoError::InvalidTag`] otherwise.
    pub fn verify(&self, msg: &[u8], expected: &[u8]) -> Result<(), CryptoError> {
        if expected.len() != self.output_len {
            return Err(CryptoError::InvalidTag);
        }
        let mut tag = vec![0u8; self.output_len];
        self.mac_oneshot(msg, &mut tag)?;
        if tag.as_slice().ct_eq(expected).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }

    /// Create an incremental streaming HMAC session.
    ///
    /// Returns a [`StreamingHashHmacSession`] that accepts data via
    /// `update()` and produces the final tag via `finalize()`.
    pub fn streaming_session(&self) -> StreamingHashHmacSession<H, F>
    where
        F: Clone,
    {
        StreamingHashHmacSession::new(self)
    }
}

// ── Incremental streaming session ────────────────────────────────────────────

/// Incremental HMAC session.
///
/// Created by [`StreamingHashHmac::streaming_session`].  Maintains the inner
/// hasher state pre-loaded with `ipad_key`, ready for message data via
/// [`update`](Self::update).  Calling [`finalize`](Self::finalize) computes
/// the outer hash and returns the final HMAC tag.
pub struct StreamingHashHmacSession<H, F>
where
    H: StreamingHash,
    F: Fn() -> H + Send,
{
    /// Inner hasher pre-loaded with `H(ipad_key ‖ …)`.
    inner: H,
    /// Outer padded key `opad_key` bytes, ready to prefix the outer hash.
    opad_key: Vec<u8>,
    /// Output length of the underlying hash.
    output_len: usize,
    /// Factory stored for the outer hash creation.
    factory: F,
}

impl<H, F> StreamingHashHmacSession<H, F>
where
    H: StreamingHash,
    F: Fn() -> H + Send + Clone,
{
    fn new(hmac: &StreamingHashHmac<H, F>) -> Self
    where
        F: Clone,
    {
        let ipad_key: Vec<u8> = hmac.padded_key.iter().map(|b| b ^ 0x36u8).collect();
        let opad_key: Vec<u8> = hmac.padded_key.iter().map(|b| b ^ 0x5cu8).collect();

        let mut inner = (hmac.factory)();
        inner.update(&ipad_key);

        Self {
            inner,
            opad_key,
            output_len: hmac.output_len,
            factory: hmac.factory.clone(),
        }
    }

    /// Feed additional message bytes into the inner hash.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalise the inner hash and compute the outer HMAC, writing the tag into
    /// `out`.
    ///
    /// Consumes `self`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BufferTooSmall`] if `out.len() < output_len`.
    pub fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < self.output_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Finalise inner hash.
        let mut inner_tag = vec![0u8; self.output_len];
        self.inner.finalize(&mut inner_tag)?;

        // Outer = H(opad_key ‖ inner_tag).
        let mut outer = (self.factory)();
        outer.update(&self.opad_key);
        outer.update(&inner_tag);
        outer.finalize(&mut out[..self.output_len])?;

        Ok(())
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Compute an HMAC tag using any [`StreamingHash`] created by `make_hash`.
///
/// This is the lowest-friction entry point: supply the key, block size,
/// expected output length, message, and a no-argument closure that returns a
/// fresh `StreamingHash`.
///
/// ```rust,ignore
/// let tag = hmac_with_streaming_hash(
///     b"key", 64, 32, b"message",
///     || oxicrypto_hash::Sha256Streaming::new(),
/// )?;
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] for zero `block_size` / `output_len`,
/// or [`CryptoError::BufferTooSmall`] if internal buffer logic fails.
pub fn hmac_with_streaming_hash<H, F>(
    key: &[u8],
    block_size: usize,
    output_len: usize,
    msg: &[u8],
    make_hash: F,
) -> Result<Vec<u8>, CryptoError>
where
    H: StreamingHash,
    F: Fn() -> H + Send,
{
    let hmac = StreamingHashHmac::new(key, block_size, output_len, make_hash)?;
    let mut tag = vec![0u8; output_len];
    hmac.mac_oneshot(msg, &mut tag)?;
    Ok(tag)
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal in-memory streaming hash for unit tests (SHA-256 via sha2 crate).
    struct SimpleSha256Hasher {
        inner: sha2::Sha256,
    }

    impl SimpleSha256Hasher {
        fn new() -> Self {
            use sha2::Digest;
            Self {
                inner: sha2::Sha256::new(),
            }
        }
    }

    impl StreamingHash for SimpleSha256Hasher {
        fn update(&mut self, data: &[u8]) {
            sha2::Digest::update(&mut self.inner, data);
        }

        fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
            use sha2::Digest;
            if out.len() < 32 {
                return Err(CryptoError::BufferTooSmall);
            }
            let result = self.inner.finalize();
            out[..32].copy_from_slice(&result);
            Ok(())
        }

        fn reset(&mut self) {
            sha2::Digest::reset(&mut self.inner);
        }
    }

    // RFC 4231 Test Case 1: key=20×0x0b, data="Hi There", SHA-256
    // Expected tag: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    #[test]
    fn test_hmac_sha256_rfc4231_tc1() {
        let key = vec![0x0bu8; 20];
        let msg = b"Hi There";
        let expected =
            hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let result = hmac_with_streaming_hash(&key, 64, 32, msg, SimpleSha256Hasher::new)
            .expect("hmac_with_streaming_hash failed");

        assert_eq!(result, expected);
    }

    // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
    // Expected (Python hmac.new("Jefe", "what do ya want for nothing?", sha256).hexdigest()):
    // 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    #[test]
    fn test_hmac_sha256_rfc4231_tc2() {
        let key = b"Jefe";
        let msg = b"what do ya want for nothing?";
        let expected =
            hex_decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

        let result = hmac_with_streaming_hash(key, 64, 32, msg, SimpleSha256Hasher::new)
            .expect("hmac_with_streaming_hash failed");

        assert_eq!(result, expected);
    }

    // Key longer than block_size: key = 131 bytes of 0xaa (> 64)
    // RFC 4231 TC5 uses such a key.
    // Expected (SHA-256): 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
    #[test]
    fn test_hmac_sha256_rfc4231_tc5_long_key() {
        let key = vec![0xaau8; 131];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected =
            hex_decode("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        let result = hmac_with_streaming_hash(&key, 64, 32, msg, SimpleSha256Hasher::new)
            .expect("hmac with long key failed");

        assert_eq!(result, expected);
    }

    // Verify: correct tag passes, incorrect tag fails.
    #[test]
    fn test_hmac_verify_correct_and_incorrect() {
        let key = b"test-key";
        let msg = b"test-message";
        let hmac = StreamingHashHmac::new(key, 64, 32, SimpleSha256Hasher::new)
            .expect("StreamingHashHmac::new failed");

        let mut tag = vec![0u8; 32];
        hmac.mac_oneshot(msg, &mut tag).expect("mac_oneshot");

        assert!(hmac.verify(msg, &tag).is_ok(), "correct tag should verify");

        // Flip one bit.
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 0x01;
        assert!(
            hmac.verify(msg, &bad_tag).is_err(),
            "flipped tag should fail"
        );
    }

    // Streaming session should produce the same tag as one-shot.
    #[test]
    fn test_streaming_session_matches_oneshot() {
        let key = b"streaming-test-key";
        let msg = b"the quick brown fox jumps over the lazy dog";

        let hmac = StreamingHashHmac::new(key, 64, 32, SimpleSha256Hasher::new)
            .expect("StreamingHashHmac::new");

        // One-shot.
        let mut tag_oneshot = vec![0u8; 32];
        hmac.mac_oneshot(msg, &mut tag_oneshot)
            .expect("mac_oneshot");

        // Streaming (clone factory pattern — F must be Clone for session).
        let hmac2 = StreamingHashHmac::new(key, 64, 32, SimpleSha256Hasher::new).expect("new2");
        let mut session = hmac2.streaming_session();
        for chunk in msg.chunks(7) {
            session.update(chunk);
        }
        let mut tag_streaming = vec![0u8; 32];
        session.finalize(&mut tag_streaming).expect("finalize");

        assert_eq!(tag_oneshot, tag_streaming);
    }

    // Different keys → different MACs.
    #[test]
    fn test_different_keys_produce_different_macs() {
        let msg = b"same message";
        let r1 =
            hmac_with_streaming_hash(b"key-alpha", 64, 32, msg, SimpleSha256Hasher::new).unwrap();
        let r2 =
            hmac_with_streaming_hash(b"key-beta", 64, 32, msg, SimpleSha256Hasher::new).unwrap();
        assert_ne!(r1, r2);
    }

    // Empty message is accepted.
    #[test]
    fn test_empty_message_accepted() {
        let result = hmac_with_streaming_hash(b"key", 64, 32, b"", SimpleSha256Hasher::new);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    // Buffer too small returns an error.
    #[test]
    fn test_buffer_too_small() {
        let hmac = StreamingHashHmac::new(b"key", 64, 32, SimpleSha256Hasher::new)
            .expect("StreamingHashHmac::new");
        let mut out = vec![0u8; 16]; // too small
        assert!(
            hmac.mac_oneshot(b"msg", &mut out).is_err(),
            "should fail with buffer too small"
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex decode"))
            .collect()
    }
}
