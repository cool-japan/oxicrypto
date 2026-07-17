//! STREAM chunked AEAD construction (Hoang-Reyhanitabar-Rogaway-Vizár 2015).
//!
//! STREAM wraps a nonce-based AEAD to provide streaming authenticated
//! encryption with per-chunk authentication.  Each chunk gets a unique nonce
//! derived from a nonce prefix and a 32-bit counter; the final chunk is
//! distinguished by a 1-byte flag.
//!
//! # Nonce layout (12-byte AES-GCM)
//!
//! ```text
//! ┌────────────── 7 bytes ──────────────┬── 4 bytes ──┬─ 1 byte ─┐
//! │            nonce prefix             │   counter   │   flag   │
//! └─────────────────────────────────────┴─────────────┴──────────┘
//! ```
//!
//! flag = 0x00 for non-final chunks, 0x01 for the final chunk.
//!
//! # Nonce layout (24-byte XChaCha20-Poly1305)
//!
//! ```text
//! ┌──────────────── 19 bytes ───────────────┬── 4 bytes ──┬─ 1 byte ─┐
//! │              nonce prefix               │   counter   │   flag   │
//! └─────────────────────────────────────────┴─────────────┴──────────┘
//! ```
//!
//! # Trait contract
//!
//! The `init` method's `nonce` parameter is the **nonce prefix** (not the
//! full per-chunk nonce).  Its required length is `NONCE_FULL - 5` bytes.
//!
//! Each `encrypt_update` call encrypts **one buffered chunk** (not the
//! supplied chunk) — the supplied chunk is stored for the next call.
//! This "look-ahead by one chunk" is necessary so `encrypt_finalize` can
//! correctly tag the last chunk with flag=0x01.

use aead::{AeadInOut, KeyInit};
use aes_gcm::Aes256Gcm as AesGcm256;
use chacha20poly1305::XChaCha20Poly1305;
use oxicrypto_core::{CryptoError, StreamingAead};
use subtle::ConstantTimeEq as _;

/// Operating mode of a streaming AEAD instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    /// `init` has been called; ready to encrypt.
    Encrypting,
    /// `init` has been called; ready to decrypt.
    Decrypting,
    /// `encrypt_finalize` or `decrypt_finalize` has been called; must call `reset`.
    Finished,
}

// ── Generic STREAM helpers ──────────────────────────────────────────────────

/// Build the per-chunk nonce from a prefix, counter, and final flag.
///
/// `prefix` has length `NONCE_FULL - 5`.
fn build_nonce<const NONCE_FULL: usize>(
    prefix: &[u8],
    counter: u32,
    is_final: bool,
) -> [u8; NONCE_FULL] {
    let mut nonce = [0u8; NONCE_FULL];
    let prefix_len = NONCE_FULL - 5;
    nonce[..prefix_len].copy_from_slice(prefix);
    let counter_bytes = counter.to_be_bytes();
    nonce[prefix_len..prefix_len + 4].copy_from_slice(&counter_bytes);
    nonce[NONCE_FULL - 1] = if is_final { 0x01 } else { 0x00 };
    nonce
}

/// Seal one STREAM chunk using the provided AEAD cipher type.
///
/// The output `ct_out` must have room for `pt.len() + tag_len` bytes.
/// Returns the number of bytes written.
fn stream_seal_chunk<C, const NONCE_FULL: usize>(
    cipher: &C,
    nonce: &[u8; NONCE_FULL],
    aad: &[u8],
    pt: &[u8],
    ct_out: &mut [u8],
) -> Result<usize, CryptoError>
where
    C: AeadInOut,
{
    let tag_len = <<C as aead::AeadCore>::TagSize as aead::array::typenum::Unsigned>::USIZE;
    let required = pt.len().checked_add(tag_len).ok_or(CryptoError::BadInput)?;
    if ct_out.len() < required {
        return Err(CryptoError::BufferTooSmall);
    }
    ct_out[..pt.len()].copy_from_slice(pt);
    let nonce_ga =
        aead::Nonce::<C>::try_from(nonce.as_ref()).map_err(|_| CryptoError::InvalidNonce)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce_ga, aad, (&mut ct_out[..pt.len()]).into())
        .map_err(|_| CryptoError::Internal("STREAM encrypt chunk failed"))?;
    ct_out[pt.len()..required].copy_from_slice(&tag);
    Ok(required)
}

/// Open one STREAM chunk; returns plaintext length on success.
fn stream_open_chunk<C, const NONCE_FULL: usize>(
    cipher: &C,
    nonce: &[u8; NONCE_FULL],
    aad: &[u8],
    ct_and_tag: &[u8],
    pt_out: &mut [u8],
) -> Result<usize, CryptoError>
where
    C: AeadInOut,
{
    let tag_len = <<C as aead::AeadCore>::TagSize as aead::array::typenum::Unsigned>::USIZE;
    if ct_and_tag.len() < tag_len {
        return Err(CryptoError::BadInput);
    }
    let pt_len = ct_and_tag.len() - tag_len;
    if pt_out.len() < pt_len {
        return Err(CryptoError::BufferTooSmall);
    }
    pt_out[..pt_len].copy_from_slice(&ct_and_tag[..pt_len]);
    let nonce_ga =
        aead::Nonce::<C>::try_from(nonce.as_ref()).map_err(|_| CryptoError::InvalidNonce)?;
    let tag_bytes = &ct_and_tag[pt_len..];
    let tag = aead::Tag::<C>::try_from(tag_bytes).map_err(|_| CryptoError::BadInput)?;
    cipher
        .decrypt_inout_detached(&nonce_ga, aad, (&mut pt_out[..pt_len]).into(), &tag)
        .map_err(|_| CryptoError::InvalidTag)?;
    Ok(pt_len)
}

// ── AES-256-GCM STREAM ────────────────────────────────────────────────────────

/// STREAM chunked AEAD using AES-256-GCM.
///
/// Nonce layout: 7-byte prefix ‖ 4-byte counter (big-endian) ‖ 1-byte flag.
///
/// Provide a 7-byte prefix to `init`.  Each `encrypt_update` or
/// `decrypt_update` call processes exactly one buffered chunk.
pub struct Aes256GcmStream {
    /// The underlying AES-256-GCM cipher, present after `init`.
    cipher: Option<AesGcm256>,
    /// 7-byte nonce prefix (nonce[0..7]).
    nonce_prefix: [u8; 7],
    /// Per-chunk counter; incremented after each chunk is processed.
    counter: u32,
    /// AAD to be applied to every chunk.
    aad: alloc::vec::Vec<u8>,
    /// Buffered chunk (one chunk look-ahead for encryption).
    pending: alloc::vec::Vec<u8>,
    /// Operating mode.
    mode: StreamMode,
}

impl core::fmt::Debug for Aes256GcmStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes256GcmStream")
            .field("mode", &self.mode)
            .field("counter", &self.counter)
            .field("pending_len", &self.pending.len())
            .finish()
    }
}

extern crate alloc;
use alloc::vec::Vec;

impl Aes256GcmStream {
    /// Full 12-byte nonce for the current chunk.
    fn current_nonce(&self, is_final: bool) -> [u8; 12] {
        build_nonce(&self.nonce_prefix, self.counter, is_final)
    }

    /// Advance the counter, returning an error if it would overflow.
    fn advance_counter(&mut self) -> Result<(), CryptoError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::Internal("STREAM counter overflow"))?;
        Ok(())
    }
}

impl StreamingAead for Aes256GcmStream {
    /// Initialise the stream.
    ///
    /// `nonce` must be exactly 7 bytes (the nonce prefix).
    fn init(key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != 7 {
            return Err(CryptoError::InvalidNonce);
        }
        let cipher = AesGcm256::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let mut nonce_prefix = [0u8; 7];
        nonce_prefix.copy_from_slice(nonce);
        Ok(Self {
            cipher: Some(cipher),
            nonce_prefix,
            counter: 0,
            aad: aad.to_vec(),
            pending: Vec::new(),
            mode: StreamMode::Encrypting,
        })
    }

    /// Encrypt one chunk.
    ///
    /// The **previously supplied** chunk (from the last `encrypt_update` call)
    /// is encrypted into `out` with a non-final nonce.  The supplied `chunk`
    /// is buffered for the next call.  On the first call, only buffering
    /// occurs; `out` receives 0 bytes.
    ///
    /// `out` must be large enough to hold the previous chunk's ciphertext +
    /// 16-byte tag (i.e. `prev_chunk.len() + 16`).
    fn encrypt_update(&mut self, chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if self.mode != StreamMode::Encrypting {
            return Err(CryptoError::BadInput);
        }
        let cipher = self.cipher.as_ref().ok_or(CryptoError::BadInput)?;

        if self.pending.is_empty() {
            // First call: buffer the incoming chunk, emit nothing.
            self.pending = chunk.to_vec();
            return Ok(0);
        }

        // Encrypt the buffered chunk with flag=0x00 (non-final).
        let nonce = self.current_nonce(false);
        let prev = core::mem::replace(&mut self.pending, chunk.to_vec());
        let written = stream_seal_chunk::<_, 12>(cipher, &nonce, &self.aad, &prev, out)?;
        self.advance_counter()?;
        Ok(written)
    }

    /// Finalize encryption by flushing the buffered last chunk with flag=0x01.
    ///
    /// `out` must hold at least `last_buffered_chunk.len() + 16` bytes.
    /// Returns the 16-byte final authentication tag (also embedded in `out`).
    fn encrypt_finalize(mut self, out: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        if self.mode != StreamMode::Encrypting {
            return Err(CryptoError::BadInput);
        }
        self.mode = StreamMode::Finished;
        let cipher = self.cipher.take().ok_or(CryptoError::BadInput)?;

        let nonce = self.current_nonce(true);
        let last = self.pending.clone();
        let written = stream_seal_chunk::<_, 12>(&cipher, &nonce, &self.aad, &last, out)?;

        // Extract the 16-byte tag from the end of what was written.
        let tag_start = written - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&out[tag_start..written]);
        Ok(tag)
    }

    /// Decrypt one chunk.
    ///
    /// Buffers the supplied ciphertext chunk.  If a previous chunk is pending,
    /// it is decrypted (with non-final nonce) into `out`.
    fn decrypt_update(&mut self, chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if self.mode != StreamMode::Decrypting {
            // Allow switching to decrypt mode on first decrypt call.
            if self.mode == StreamMode::Encrypting && self.counter == 0 && self.pending.is_empty() {
                self.mode = StreamMode::Decrypting;
            } else {
                return Err(CryptoError::BadInput);
            }
        }
        let cipher = self.cipher.as_ref().ok_or(CryptoError::BadInput)?;

        if self.pending.is_empty() {
            self.pending = chunk.to_vec();
            return Ok(0);
        }

        // Decrypt the buffered chunk with flag=0x00 (non-final).
        let nonce = self.current_nonce(false);
        let prev = core::mem::replace(&mut self.pending, chunk.to_vec());
        let written = stream_open_chunk::<_, 12>(cipher, &nonce, &self.aad, &prev, out)?;
        self.advance_counter()?;
        Ok(written)
    }

    /// Verify and finalize decryption of the buffered last chunk.
    ///
    /// `expected_tag` is the 16-byte tag from the last ciphertext chunk.
    /// The buffered chunk must already contain `ciphertext || tag`.
    fn decrypt_finalize(mut self, expected_tag: &[u8]) -> Result<(), CryptoError> {
        if self.mode != StreamMode::Decrypting {
            return Err(CryptoError::BadInput);
        }
        self.mode = StreamMode::Finished;
        let cipher = self.cipher.take().ok_or(CryptoError::BadInput)?;

        // The buffered last chunk already contains ct || tag.
        // But decrypt_finalize's expected_tag is provided externally.
        // We verify the buffered pending chunk includes that tag.
        let pending = self.pending.clone();
        let tag_len = 16usize;
        if pending.len() < tag_len {
            return Err(CryptoError::BadInput);
        }

        // Check expected_tag matches what's in the pending buffer.
        let embedded_tag = &pending[pending.len() - tag_len..];
        if !bool::from(expected_tag.ct_eq(embedded_tag)) {
            return Err(CryptoError::InvalidTag);
        }

        let nonce = self.current_nonce(true);
        let mut pt = alloc::vec![0u8; pending.len() - tag_len];
        stream_open_chunk::<_, 12>(&cipher, &nonce, &self.aad, &pending, &mut pt).map(|_| ())
    }

    /// Reset the stream to its initial uninitialized state.
    fn reset(&mut self) {
        self.counter = 0;
        self.pending.clear();
        self.mode = StreamMode::Encrypting;
        self.cipher = None;
    }
}

// ── ChaCha20-Poly1305 STREAM ──────────────────────────────────────────────────

/// STREAM chunked AEAD using XChaCha20-Poly1305.
///
/// Nonce layout: 19-byte prefix ‖ 4-byte counter (big-endian) ‖ 1-byte flag.
///
/// Provide a 19-byte prefix to `init`.
pub struct ChaCha20Poly1305Stream {
    cipher: Option<XChaCha20Poly1305>,
    nonce_prefix: [u8; 19],
    counter: u32,
    aad: Vec<u8>,
    pending: Vec<u8>,
    mode: StreamMode,
}

impl core::fmt::Debug for ChaCha20Poly1305Stream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20Poly1305Stream")
            .field("mode", &self.mode)
            .field("counter", &self.counter)
            .field("pending_len", &self.pending.len())
            .finish()
    }
}

impl ChaCha20Poly1305Stream {
    fn current_nonce(&self, is_final: bool) -> [u8; 24] {
        build_nonce(&self.nonce_prefix, self.counter, is_final)
    }

    fn advance_counter(&mut self) -> Result<(), CryptoError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::Internal("STREAM counter overflow"))?;
        Ok(())
    }
}

impl StreamingAead for ChaCha20Poly1305Stream {
    /// Initialise the stream.
    ///
    /// `nonce` must be exactly 19 bytes (XChaCha20 nonce prefix).
    fn init(key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != 19 {
            return Err(CryptoError::InvalidNonce);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let mut nonce_prefix = [0u8; 19];
        nonce_prefix.copy_from_slice(nonce);
        Ok(Self {
            cipher: Some(cipher),
            nonce_prefix,
            counter: 0,
            aad: aad.to_vec(),
            pending: Vec::new(),
            mode: StreamMode::Encrypting,
        })
    }

    fn encrypt_update(&mut self, chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if self.mode != StreamMode::Encrypting {
            return Err(CryptoError::BadInput);
        }
        let cipher = self.cipher.as_ref().ok_or(CryptoError::BadInput)?;

        if self.pending.is_empty() {
            self.pending = chunk.to_vec();
            return Ok(0);
        }

        let nonce = self.current_nonce(false);
        let prev = core::mem::replace(&mut self.pending, chunk.to_vec());
        let written = stream_seal_chunk::<_, 24>(cipher, &nonce, &self.aad, &prev, out)?;
        self.advance_counter()?;
        Ok(written)
    }

    fn encrypt_finalize(mut self, out: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        if self.mode != StreamMode::Encrypting {
            return Err(CryptoError::BadInput);
        }
        self.mode = StreamMode::Finished;
        let cipher = self.cipher.take().ok_or(CryptoError::BadInput)?;

        let nonce = self.current_nonce(true);
        let last = self.pending.clone();
        let written = stream_seal_chunk::<_, 24>(&cipher, &nonce, &self.aad, &last, out)?;

        let tag_start = written - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&out[tag_start..written]);
        Ok(tag)
    }

    fn decrypt_update(&mut self, chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if self.mode != StreamMode::Decrypting {
            if self.mode == StreamMode::Encrypting && self.counter == 0 && self.pending.is_empty() {
                self.mode = StreamMode::Decrypting;
            } else {
                return Err(CryptoError::BadInput);
            }
        }
        let cipher = self.cipher.as_ref().ok_or(CryptoError::BadInput)?;

        if self.pending.is_empty() {
            self.pending = chunk.to_vec();
            return Ok(0);
        }

        let nonce = self.current_nonce(false);
        let prev = core::mem::replace(&mut self.pending, chunk.to_vec());
        let written = stream_open_chunk::<_, 24>(cipher, &nonce, &self.aad, &prev, out)?;
        self.advance_counter()?;
        Ok(written)
    }

    fn decrypt_finalize(mut self, expected_tag: &[u8]) -> Result<(), CryptoError> {
        if self.mode != StreamMode::Decrypting {
            return Err(CryptoError::BadInput);
        }
        self.mode = StreamMode::Finished;
        let cipher = self.cipher.take().ok_or(CryptoError::BadInput)?;

        let pending = self.pending.clone();
        let tag_len = 16usize;
        if pending.len() < tag_len {
            return Err(CryptoError::BadInput);
        }

        let embedded_tag = &pending[pending.len() - tag_len..];
        if !bool::from(expected_tag.ct_eq(embedded_tag)) {
            return Err(CryptoError::InvalidTag);
        }

        let nonce = self.current_nonce(true);
        let mut pt = alloc::vec![0u8; pending.len() - tag_len];
        stream_open_chunk::<_, 24>(&cipher, &nonce, &self.aad, &pending, &mut pt).map(|_| ())
    }

    fn reset(&mut self) {
        self.counter = 0;
        self.pending.clear();
        self.mode = StreamMode::Encrypting;
        self.cipher = None;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_256: [u8; 32] = [0x42u8; 32];
    const NONCE_PREFIX_7: [u8; 7] = [0x24u8; 7];
    const NONCE_PREFIX_19: [u8; 19] = [0x24u8; 19];
    const AAD: &[u8] = b"stream aad";
    const TAG_LEN: usize = 16;

    /// Encrypt `chunks` using `Aes256GcmStream`, returning `(Vec<ct_chunks>, final_tag)`.
    ///
    /// Each element of the returned `Vec` is `ciphertext || 16-byte tag` for
    /// one chunk.  The last element corresponds to the final (flag=1) chunk.
    fn encrypt_chunks_aes256(chunks: &[&[u8]]) -> (Vec<Vec<u8>>, [u8; 16]) {
        assert!(!chunks.is_empty());
        let mut enc = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init enc");
        let mut ct_chunks: Vec<Vec<u8>> = Vec::new();

        // encrypt_update(chunk_i) emits the encryption of chunk_{i-1} (look-ahead buffering).
        // The output buffer must be large enough for the *previous* (pending) chunk + tag.
        // We use the largest possible chunk size across all chunks for simplicity.
        let max_chunk_len = chunks.iter().map(|c| c.len()).max().unwrap_or(0);
        let buf_cap = max_chunk_len + TAG_LEN;

        for chunk in chunks {
            let mut buf = alloc::vec![0u8; buf_cap];
            let written = enc.encrypt_update(chunk, &mut buf).expect("encrypt_update");
            if written > 0 {
                ct_chunks.push(buf[..written].to_vec());
            }
        }

        // Finalize flushes the last buffered chunk with flag=1.
        let last = *chunks.last().unwrap();
        let mut final_buf = alloc::vec![0u8; last.len() + TAG_LEN];
        let tag = enc
            .encrypt_finalize(&mut final_buf)
            .expect("encrypt_finalize");
        ct_chunks.push(final_buf[..last.len() + TAG_LEN].to_vec());
        (ct_chunks, tag)
    }

    /// Decrypt `ct_chunks` with `Aes256GcmStream`, returning the concatenated plaintext.
    ///
    /// `final_tag` is the tag returned by `encrypt_finalize` / embedded in the last chunk.
    fn decrypt_chunks_aes256(ct_chunks: &[Vec<u8>], final_tag: &[u8; 16]) -> Vec<u8> {
        let mut dec = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init dec");
        dec.mode = StreamMode::Decrypting;
        let mut plaintext: Vec<u8> = Vec::new();

        // Feed all ct chunks via decrypt_update.
        // The first call just buffers; subsequent calls decrypt the prior buffered chunk.
        for ct in ct_chunks {
            let buf_cap = ct.len(); // plaintext is at most ct.len() - TAG_LEN
            let mut buf = alloc::vec![0u8; buf_cap];
            let written = dec.decrypt_update(ct, &mut buf).expect("decrypt_update");
            plaintext.extend_from_slice(&buf[..written]);
        }

        // Finalize: decrypt the last buffered ct chunk (with flag=1 nonce) and verify tag.
        dec.decrypt_finalize(final_tag).expect("decrypt_finalize");
        // The last chunk's plaintext is not returned by decrypt_finalize in our trait.
        // We recover it by subtracting the tag from the last ct chunk.
        // (decrypt_finalize internally verifies; plaintext was recovered into the internal buffer.)
        // We need to extract it separately — re-decrypt the final chunk manually.
        let last_ct = ct_chunks.last().unwrap();
        let pt_len = last_ct.len().saturating_sub(TAG_LEN);
        // Re-run a fresh decrypt just to extract the final plaintext bytes.
        let mut dec2 = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init dec2");
        dec2.mode = StreamMode::Decrypting;
        for ct in ct_chunks {
            let mut buf = alloc::vec![0u8; ct.len()];
            let written = dec2.decrypt_update(ct, &mut buf).expect("decrypt_update2");
            if written > 0 {
                // These chunks were already added by the first pass; skip here.
                let _ = written;
            }
        }
        // After all chunks fed, the last chunk is pending in dec2.
        // We can't call decrypt_finalize twice on the same stream (it's consumed).
        // Instead, decrypt the last ct chunk directly using the known key/nonce.
        let nonce_counter = (ct_chunks.len() as u32).wrapping_sub(1);
        let nonce: [u8; 12] = build_nonce(&NONCE_PREFIX_7, nonce_counter, true);
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&KEY_256).expect("cipher");
        let nonce_ga =
            aead::Nonce::<aes_gcm::Aes256Gcm>::try_from(nonce.as_ref()).expect("nonce length");
        let mut last_pt = last_ct[..pt_len].to_vec();
        let tag_bytes = &last_ct[pt_len..];
        let tag_ga = aead::Tag::<aes_gcm::Aes256Gcm>::try_from(tag_bytes).expect("tag length");
        cipher
            .decrypt_inout_detached(&nonce_ga, AAD, (&mut last_pt[..]).into(), &tag_ga)
            .expect("last chunk decrypt");
        plaintext.extend_from_slice(&last_pt);
        plaintext
    }

    #[test]
    fn aes256gcm_stream_three_chunks() {
        let chunks: &[&[u8]] = &[b"chunk-one---", b"chunk-two---", b"chunk-three"];
        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();

        let (ct_chunks, final_tag) = encrypt_chunks_aes256(chunks);
        let recovered = decrypt_chunks_aes256(&ct_chunks, &final_tag);
        assert_eq!(recovered, expected, "three-chunk round-trip failed");
    }

    #[test]
    fn aes256gcm_stream_single_chunk() {
        let chunk = b"only one chunk";

        let mut enc = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init");
        // First update: buffers the chunk, emits nothing.
        let mut buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let written = enc.encrypt_update(chunk, &mut buf).expect("update");
        assert_eq!(written, 0);

        // Finalize: encrypts the buffered chunk with flag=1.
        let mut final_buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let tag = enc.encrypt_finalize(&mut final_buf).expect("finalize");
        assert_eq!(final_buf.len(), chunk.len() + TAG_LEN);

        // Decrypt: first update buffers the ct chunk.
        let mut dec = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init dec");
        dec.mode = StreamMode::Decrypting;
        let mut pt_buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let w = dec
            .decrypt_update(&final_buf, &mut pt_buf)
            .expect("decrypt_update");
        assert_eq!(w, 0, "first update must buffer, not emit");
        // Finalize decrypts the buffered final chunk.
        dec.decrypt_finalize(&tag).expect("decrypt_finalize");
    }

    #[test]
    fn aes256gcm_stream_tamper_middle_chunk_fails() {
        // Encrypt 3 chunks so we get a middle ct chunk to tamper with.
        let chunks: &[&[u8]] = &[b"chunk-A-data---", b"chunk-B-tamper-", b"chunk-C-final--"];
        let (mut ct_chunks, final_tag) = encrypt_chunks_aes256(chunks);

        // Tamper with the middle chunk (index 0 of ct_chunks corresponds to chunk-A
        // because of the look-ahead: encrypt_update(chunk-A) emits nothing,
        // encrypt_update(chunk-B) emits ct of chunk-A,
        // encrypt_update(chunk-C) emits ct of chunk-B,
        // encrypt_finalize emits ct of chunk-C).
        //
        // ct_chunks[0] = ct of chunk-A (flag=0, counter=0)
        // ct_chunks[1] = ct of chunk-B (flag=0, counter=1)
        // ct_chunks[2] = ct of chunk-C (flag=1, counter=2)
        ct_chunks[1][0] ^= 0xFF; // tamper chunk-B ciphertext

        let mut dec = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init dec");
        dec.mode = StreamMode::Decrypting;

        // Feed ct_chunks[0]: buffers (returns 0).
        let mut pt_buf = alloc::vec![0u8; ct_chunks[0].len()];
        let w0 = dec
            .decrypt_update(&ct_chunks[0], &mut pt_buf)
            .expect("update0");
        assert_eq!(w0, 0);

        // Feed ct_chunks[1]: decrypts buffered ct_chunks[0], buffers ct_chunks[1] (tampered).
        // Should succeed (ct_chunks[0] is not tampered).
        let mut pt_buf1 = alloc::vec![0u8; ct_chunks[0].len()];
        let w1 = dec
            .decrypt_update(&ct_chunks[1], &mut pt_buf1)
            .expect("update1");
        assert!(w1 > 0, "should have emitted decrypted chunk-A");

        // Feed ct_chunks[2]: decrypts the tampered ct_chunks[1] — should fail.
        let mut pt_buf2 = alloc::vec![0u8; ct_chunks[1].len()];
        let result = dec.decrypt_update(&ct_chunks[2], &mut pt_buf2);
        assert!(
            matches!(result, Err(CryptoError::InvalidTag)),
            "expected InvalidTag on tampered chunk, got: {:?}",
            result
        );
        // final_tag is not needed since we expect failure before decrypt_finalize.
        let _ = final_tag;
    }

    #[test]
    fn aes256gcm_stream_tamper_final_tag_fails() {
        let chunks: &[&[u8]] = &[b"single"];
        let (ct_chunks, mut final_tag) = encrypt_chunks_aes256(chunks);

        // Tamper with the final tag.
        final_tag[0] ^= 0xFF;

        let mut dec = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init dec");
        dec.mode = StreamMode::Decrypting;
        let mut pt_buf = alloc::vec![0u8; ct_chunks[0].len()];
        dec.decrypt_update(&ct_chunks[0], &mut pt_buf)
            .expect("update");
        let result = dec.decrypt_finalize(&final_tag);
        assert!(
            matches!(result, Err(CryptoError::InvalidTag)),
            "expected InvalidTag, got: {:?}",
            result
        );
    }

    #[test]
    fn aes256gcm_stream_reject_update_after_finalize() {
        // After encrypt_finalize (which consumes enc), you cannot call encrypt_update.
        // This is enforced at compile time by consuming `self` in encrypt_finalize.
        // We just verify the finalize path works correctly.
        let chunk = b"data";
        let mut enc = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init");
        let mut buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        enc.encrypt_update(chunk, &mut buf).expect("update");
        let mut final_buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let _tag = enc.encrypt_finalize(&mut final_buf).expect("finalize");
        // enc is moved/consumed; further calls would not compile.
    }

    #[test]
    fn chacha20poly1305_stream_single_chunk_round_trip() {
        let chunk = b"xchacha20 stream chunk";

        let mut enc = ChaCha20Poly1305Stream::init(&KEY_256, &NONCE_PREFIX_19, AAD).expect("init");
        let mut buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let w = enc.encrypt_update(chunk, &mut buf).expect("update");
        assert_eq!(w, 0);

        let mut final_buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let tag = enc.encrypt_finalize(&mut final_buf).expect("finalize");

        let mut dec =
            ChaCha20Poly1305Stream::init(&KEY_256, &NONCE_PREFIX_19, AAD).expect("init dec");
        dec.mode = StreamMode::Decrypting;
        let mut pt_buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let _w = dec
            .decrypt_update(&final_buf, &mut pt_buf)
            .expect("decrypt_update");
        dec.decrypt_finalize(&tag).expect("decrypt_finalize");
    }

    #[test]
    fn aes256gcm_stream_wrong_nonce_prefix_length() {
        let result = Aes256GcmStream::init(&KEY_256, &[0u8; 12], AAD);
        assert!(
            matches!(result, Err(CryptoError::InvalidNonce)),
            "expected InvalidNonce, got: {:?}",
            result.as_ref().map(|_| ()).map_err(|e| format!("{e:?}"))
        );
    }

    #[test]
    fn chacha20poly1305_stream_wrong_nonce_prefix_length() {
        let result = ChaCha20Poly1305Stream::init(&KEY_256, &[0u8; 12], AAD);
        assert!(
            matches!(result, Err(CryptoError::InvalidNonce)),
            "expected InvalidNonce, got: {:?}",
            result.as_ref().map(|_| ()).map_err(|e| format!("{e:?}"))
        );
    }

    #[test]
    fn aes256gcm_stream_reset_clears_state() {
        // Initialise, feed one chunk (buffers it), then reset.
        // After reset, counter must be 0, pending must be empty,
        // and the mode must be back to Encrypting.
        let chunk = b"some data";
        let mut enc = Aes256GcmStream::init(&KEY_256, &NONCE_PREFIX_7, AAD).expect("init");
        assert_eq!(enc.counter, 0, "initial counter");
        assert!(enc.pending.is_empty(), "initial pending");
        assert_eq!(enc.mode, StreamMode::Encrypting, "initial mode");

        let mut buf = alloc::vec![0u8; chunk.len() + TAG_LEN];
        let w = enc.encrypt_update(chunk, &mut buf).expect("encrypt_update");
        assert_eq!(w, 0, "first update buffers; emits nothing");
        assert!(!enc.pending.is_empty(), "pending filled after update");

        // Reset clears cipher, counter, pending, and sets mode to Encrypting.
        enc.reset();
        assert_eq!(enc.counter, 0, "counter after reset");
        assert!(enc.pending.is_empty(), "pending after reset");
        assert_eq!(enc.mode, StreamMode::Encrypting, "mode after reset");
        assert!(enc.cipher.is_none(), "cipher cleared after reset");
    }
}
