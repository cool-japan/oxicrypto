#![forbid(unsafe_code)]

//! Pure Rust AEAD implementations for the OxiCrypto stack.
//!
//! | Algorithm | Module | Key / Nonce |
//! |-----------|--------|-------------|
//! | AES-128-GCM | (inline) | 16 / 12 bytes |
//! | AES-256-GCM | (inline) | 32 / 12 bytes |
//! | ChaCha20-Poly1305 | (inline) | 32 / 12 bytes |
//! | AES-128-GCM-SIV | [`aes_gcm_siv`] | 16 / 12 bytes |
//! | AES-256-GCM-SIV | [`aes_gcm_siv`] | 32 / 12 bytes |
//! | XChaCha20-Poly1305 | [`xchacha20`] | 32 / 24 bytes |
//! | AES-128-CCM | [`ccm`] | 16 / 13 bytes |
//! | AES-256-CCM | [`ccm`] | 32 / 13 bytes |
//! | AES-128-OCB3 | [`ocb3_impl`] | 16 / 12 bytes |
//! | AES-256-OCB3 | [`ocb3_impl`] | 32 / 12 bytes |
//! | Deoxys-II-128-128 | [`deoxys`] | 16 / 16 bytes |
//!
//! # Streaming AEAD (STREAM construction)
//!
//! [`stream::Aes256GcmStream`] and [`stream::ChaCha20Poly1305Stream`] implement
//! the `StreamingAead` trait using the STREAM chunked construction
//! (Hoang-Reyhanitabar-Rogaway-Vizár 2015).
//!
//! # Nonce sequences
//!
//! [`nonce_seq::Nonce12`] and [`nonce_seq::Nonce24`] provide monotonic nonce
//! generators suitable for AES-GCM / XChaCha20 respectively.
//!
//! # Key Wrap (RFC 3394)
//!
//! [`keywrap`] provides AES-128-KW and AES-256-KW for wrapping key material.
//! This is a standalone API that does **not** implement the `Aead` trait.
//!
//! # SealedBox
//!
//! [`sealed_box`] provides `seal_box` / `open_box` helpers that prepend a
//! randomly-generated nonce to the ciphertext as a single opaque blob.
//!
//! # Random-nonce helper
//!
//! [`seal_with_random_nonce`] encrypts plaintext with an on-the-fly random
//! nonce and returns `(nonce, ciphertext_with_tag)` separately.

extern crate alloc;

pub mod aes_gcm_siv;
pub mod ccm;
pub mod deoxys;
pub(crate) mod deoxys_bc;
pub mod keywrap;
pub mod nonce_seq;
pub mod ocb3_impl;
pub mod sealed_box;
pub mod stream;
pub mod xchacha20;

pub use aes_gcm_siv::{AesGcmSiv128, AesGcmSiv256};
pub use ccm::{Aes128Ccm, Aes256Ccm};
pub use deoxys::Deoxys2_128;
pub use keywrap::{aes128_key_unwrap, aes128_key_wrap, aes256_key_unwrap, aes256_key_wrap};
pub use nonce_seq::{Nonce12, Nonce24, NonceSequence};
pub use ocb3_impl::{Aes128Ocb3, Aes256Ocb3};
pub use sealed_box::{open_box, seal_box};
pub use stream::{Aes256GcmStream, ChaCha20Poly1305Stream};
pub use xchacha20::XChaCha20Poly1305;

// ── Random-nonce helper ───────────────────────────────────────────────────────

/// Encrypt `plaintext` with a freshly-generated random nonce.
///
/// Returns `(nonce, ciphertext_with_tag)` as separate `Vec<u8>` buffers.
/// Use this when the transport layer carries the nonce and ciphertext in
/// separate fields.  For an all-in-one wire format, prefer [`seal_box`].
///
/// # Arguments
///
/// * `aead`      — AEAD algorithm instance.
/// * `key`       — symmetric key (must have length `aead.key_len()`).
/// * `aad`       — additional authenticated data (may be empty).
/// * `plaintext` — message to encrypt.
/// * `rng`       — cryptographically-secure random source.
///
/// # Errors
///
/// * Propagates any error from `rng.fill` or `aead.seal_to_vec`.
pub fn seal_with_random_nonce(
    aead: &dyn oxicrypto_core::Aead,
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut dyn oxicrypto_core::Rng,
) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), oxicrypto_core::CryptoError> {
    let nonce_len = aead.nonce_len();
    let mut nonce = alloc::vec![0u8; nonce_len];
    rng.fill(&mut nonce)?;
    let ct = aead.seal_to_vec(key, &nonce, aad, plaintext)?;
    Ok((nonce, ct))
}

use aead::{AeadInPlace, KeyInit, KeySizeUser};
use oxicrypto_core::{Aead, CryptoError};

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Size parameters for a particular AEAD instantiation.
struct AeadParams {
    key_len: usize,
    nonce_len: usize,
    tag_len: usize,
}

/// Perform AEAD seal using the `AeadInPlace` interface to avoid heap allocation.
///
/// The output `ct_out` must be at least `pt.len() + params.tag_len` bytes.
/// Returns `pt.len() + tag_len`.
fn seal_in_place<C: AeadInPlace + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct_out: &mut [u8],
    params: AeadParams,
) -> Result<usize, CryptoError> {
    if key.len() != params.key_len {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != params.nonce_len {
        return Err(CryptoError::InvalidNonce);
    }
    let required = pt
        .len()
        .checked_add(params.tag_len)
        .ok_or(CryptoError::BadInput)?;
    if ct_out.len() < required {
        return Err(CryptoError::BufferTooSmall);
    }

    // Copy plaintext into the output buffer; the tag is appended after.
    ct_out[..pt.len()].copy_from_slice(pt);

    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
    let tag = cipher
        .encrypt_in_place_detached(nonce_arr, aad, &mut ct_out[..pt.len()])
        .map_err(|_| CryptoError::Internal("AEAD encrypt failed"))?;
    ct_out[pt.len()..required].copy_from_slice(&tag);
    Ok(required)
}

/// Perform AEAD open using the `AeadInPlace` interface.
///
/// `ct` must be at least `params.tag_len` bytes (ciphertext ‖ tag).
/// `pt_out` must be at least `ct.len() - params.tag_len` bytes.
/// Returns the number of plaintext bytes written.
fn open_in_place<C: AeadInPlace + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt_out: &mut [u8],
    params: AeadParams,
) -> Result<usize, CryptoError> {
    if key.len() != params.key_len {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != params.nonce_len {
        return Err(CryptoError::InvalidNonce);
    }
    if ct.len() < params.tag_len {
        return Err(CryptoError::BadInput);
    }
    let pt_len = ct.len() - params.tag_len;
    if pt_out.len() < pt_len {
        return Err(CryptoError::BufferTooSmall);
    }

    pt_out[..pt_len].copy_from_slice(&ct[..pt_len]);

    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
    let tag_bytes = &ct[pt_len..];
    if tag_bytes.len() != params.tag_len {
        return Err(CryptoError::BadInput);
    }
    let tag = aead::Tag::<C>::clone_from_slice(tag_bytes);

    cipher
        .decrypt_in_place_detached(nonce_arr, aad, &mut pt_out[..pt_len], &tag)
        .map_err(|_| CryptoError::InvalidTag)?;

    Ok(pt_len)
}

// ── AES-128-GCM ───────────────────────────────────────────────────────────────

/// AES-128-GCM authenticated encryption.
///
/// Key: 16 bytes, nonce: 12 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128Gcm;

impl Aead for Aes128Gcm {
    fn name(&self) -> &'static str {
        "AES-128-GCM"
    }
    fn key_len(&self) -> usize {
        aes_gcm::Aes128Gcm::key_size()
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        seal_in_place::<aes_gcm::Aes128Gcm>(
            key,
            nonce,
            aad,
            pt,
            ct_out,
            AeadParams {
                key_len: 16,
                nonce_len: 12,
                tag_len: 16,
            },
        )
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        open_in_place::<aes_gcm::Aes128Gcm>(
            key,
            nonce,
            aad,
            ct,
            pt_out,
            AeadParams {
                key_len: 16,
                nonce_len: 12,
                tag_len: 16,
            },
        )
    }
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

/// AES-256-GCM authenticated encryption.
///
/// Key: 32 bytes, nonce: 12 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes256Gcm;

impl Aead for Aes256Gcm {
    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }
    fn key_len(&self) -> usize {
        aes_gcm::Aes256Gcm::key_size()
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        seal_in_place::<aes_gcm::Aes256Gcm>(
            key,
            nonce,
            aad,
            pt,
            ct_out,
            AeadParams {
                key_len: 32,
                nonce_len: 12,
                tag_len: 16,
            },
        )
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        open_in_place::<aes_gcm::Aes256Gcm>(
            key,
            nonce,
            aad,
            ct,
            pt_out,
            AeadParams {
                key_len: 32,
                nonce_len: 12,
                tag_len: 16,
            },
        )
    }
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────────

/// ChaCha20-Poly1305 authenticated encryption.
///
/// Key: 32 bytes, nonce: 12 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChaCha20Poly1305;

impl Aead for ChaCha20Poly1305 {
    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }
    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        seal_in_place::<chacha20poly1305::ChaCha20Poly1305>(
            key,
            nonce,
            aad,
            pt,
            ct_out,
            AeadParams {
                key_len: 32,
                nonce_len: 12,
                tag_len: 16,
            },
        )
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        open_in_place::<chacha20poly1305::ChaCha20Poly1305>(
            key,
            nonce,
            aad,
            ct,
            pt_out,
            AeadParams {
                key_len: 32,
                nonce_len: 12,
                tag_len: 16,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_128: [u8; 16] = [0x42u8; 16];
    const KEY_256: [u8; 32] = [0x42u8; 32];
    const NONCE_12: [u8; 12] = [0x24u8; 12];
    const AAD: &[u8] = b"additional authenticated data";
    const PLAINTEXT: &[u8] = b"hello, oxicrypto!";

    fn round_trip<A: Aead>(aead: &A, key: &[u8]) {
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(key, &NONCE_12, AAD, PLAINTEXT, &mut ct)
            .expect("seal failed");
        assert_eq!(written, PLAINTEXT.len() + aead.tag_len());

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let recovered = aead
            .open(key, &NONCE_12, AAD, &ct[..written], &mut pt)
            .expect("open failed");
        assert_eq!(recovered, PLAINTEXT.len());
        assert_eq!(&pt[..recovered], PLAINTEXT);
    }

    fn wrong_key_fails<A: Aead>(aead: &A, good_key: &[u8], wrong_key: &[u8]) {
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(good_key, &NONCE_12, AAD, PLAINTEXT, &mut ct)
            .unwrap();

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let result = aead.open(wrong_key, &NONCE_12, AAD, &ct[..written], &mut pt);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn aes128gcm_round_trip() {
        round_trip(&Aes128Gcm, &KEY_128);
    }

    #[test]
    fn aes256gcm_round_trip() {
        round_trip(&Aes256Gcm, &KEY_256);
    }

    #[test]
    fn chacha20poly1305_round_trip() {
        round_trip(&ChaCha20Poly1305, &KEY_256);
    }

    #[test]
    fn aes128gcm_wrong_key_fails() {
        wrong_key_fails(&Aes128Gcm, &KEY_128, &[0x00u8; 16]);
    }

    #[test]
    fn aes256gcm_wrong_key_fails() {
        wrong_key_fails(&Aes256Gcm, &KEY_256, &[0x00u8; 32]);
    }

    #[test]
    fn chacha20poly1305_wrong_key_fails() {
        wrong_key_fails(&ChaCha20Poly1305, &KEY_256, &[0x00u8; 32]);
    }

    #[test]
    fn invalid_key_length() {
        let aead = Aes256Gcm;
        let mut ct = vec![0u8; PLAINTEXT.len() + 16];
        let result = aead.seal(&[0u8; 16], &NONCE_12, AAD, PLAINTEXT, &mut ct);
        assert_eq!(result, Err(CryptoError::InvalidKey));
    }

    // ── seal_with_random_nonce tests ─────────────────────────────────────────

    /// Deterministic counter RNG for tests.
    struct CounterRng {
        counter: u8,
    }

    impl CounterRng {
        fn new() -> Self {
            Self { counter: 0x11 }
        }
    }

    impl oxicrypto_core::Rng for CounterRng {
        fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
            for b in dst.iter_mut() {
                *b = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn seal_with_random_nonce_aes128gcm_round_trip() {
        let aead = Aes128Gcm;
        let mut rng = CounterRng::new();

        let (nonce, ct) = seal_with_random_nonce(&aead, &KEY_128, AAD, PLAINTEXT, &mut rng)
            .expect("seal_with_random_nonce failed");

        assert_eq!(
            nonce.len(),
            aead.nonce_len(),
            "nonce length must match aead.nonce_len()"
        );
        assert_eq!(
            ct.len(),
            PLAINTEXT.len() + aead.tag_len(),
            "ct length must be pt+tag"
        );

        // Nonce is produced by our counter RNG — verify it is the expected prefix.
        let expected_nonce: alloc::vec::Vec<u8> =
            (0u8..12).map(|i| 0x11_u8.wrapping_add(i)).collect();
        assert_eq!(nonce, expected_nonce, "nonce must match RNG output");

        // Decrypt with the separately returned nonce.
        let recovered = aead
            .open_to_vec(&KEY_128, &nonce, AAD, &ct)
            .expect("open_to_vec after seal_with_random_nonce failed");
        assert_eq!(
            recovered.as_slice(),
            PLAINTEXT,
            "round-trip must recover plaintext"
        );
    }

    #[test]
    fn seal_with_random_nonce_returns_separate_nonce_and_ct() {
        // Verify that (nonce, ct) are distinct buffers — nonce is NOT prepended in ct.
        let aead = Aes256Gcm;
        let mut rng = CounterRng::new();

        let (nonce, ct) = seal_with_random_nonce(&aead, &KEY_256, AAD, PLAINTEXT, &mut rng)
            .expect("seal_with_random_nonce failed");

        // ct starts with ciphertext, NOT nonce bytes
        assert_eq!(ct.len(), PLAINTEXT.len() + aead.tag_len());
        // nonce and ct are independent
        assert_eq!(nonce.len(), aead.nonce_len());
        assert_ne!(
            nonce.as_slice(),
            &ct[..nonce.len()],
            "nonce must not be embedded in ct"
        );
    }

    #[test]
    fn seal_with_random_nonce_rng_failure_propagates() {
        struct AlwaysFailRng;
        impl oxicrypto_core::Rng for AlwaysFailRng {
            fn fill(&mut self, _dst: &mut [u8]) -> Result<(), CryptoError> {
                Err(CryptoError::Rng)
            }
        }
        let aead = Aes128Gcm;
        let result = seal_with_random_nonce(&aead, &KEY_128, AAD, PLAINTEXT, &mut AlwaysFailRng);
        assert_eq!(result, Err(CryptoError::Rng), "RNG failure must propagate");
    }
}
