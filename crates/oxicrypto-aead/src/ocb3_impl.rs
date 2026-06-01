//! AES-OCB3 authenticated encryption (RFC 7253).
//!
//! OCB3 is an offset codebook mode of operation that provides both
//! confidentiality and authenticity in a single pass, making it one of
//! the most efficient AEAD constructions for hardware-backed AES.
//!
//! | Algorithm      | Key  | Nonce | Tag  |
//! |----------------|------|-------|------|
//! | AES-128-OCB3   | 16 B | 12 B  | 16 B |
//! | AES-256-OCB3   | 32 B | 12 B  | 16 B |
//!
//! **Patent note**: OCB3 is covered by patents held by Phillip Rogaway.
//! A royalty-free license is available for open-source software and for
//! military use. See <https://www.rfc-editor.org/rfc/rfc7253#section-1.1>.

use aead::{AeadInPlace, KeyInit, KeySizeUser};
// ocb3 0.1.0 depends on cipher 0.4 / aes 0.8.x; use the aes re-exported by
// aes-gcm (which also depends on aes 0.8.x) so the types are compatible.
use aes_gcm::aes::{Aes128, Aes256};
use ocb3::aead::consts::{U12, U16};
use ocb3::Ocb3;
use oxicrypto_core::{Aead, CryptoError};

// ── Internal type aliases ──────────────────────────────────────────────────────

/// OCB3 backend with AES-128, 12-byte nonce, 16-byte tag.
type Ocb3Aes128 = Ocb3<Aes128, U12, U16>;
/// OCB3 backend with AES-256, 12-byte nonce, 16-byte tag.
type Ocb3Aes256 = Ocb3<Aes256, U12, U16>;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

// ── Internal helpers ───────────────────────────────────────────────────────────

fn ocb3_seal<C>(
    key: &[u8],
    key_len: usize,
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct_out: &mut [u8],
) -> Result<usize, CryptoError>
where
    C: AeadInPlace + KeyInit + KeySizeUser,
{
    if key.len() != key_len {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonce);
    }
    let required = pt.len().checked_add(TAG_LEN).ok_or(CryptoError::BadInput)?;
    if ct_out.len() < required {
        return Err(CryptoError::BufferTooSmall);
    }

    ct_out[..pt.len()].copy_from_slice(pt);

    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
    let tag = cipher
        .encrypt_in_place_detached(nonce_arr, aad, &mut ct_out[..pt.len()])
        .map_err(|_| CryptoError::Internal("OCB3 encrypt failed"))?;
    ct_out[pt.len()..required].copy_from_slice(&tag);
    Ok(required)
}

fn ocb3_open<C>(
    key: &[u8],
    key_len: usize,
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    pt_out: &mut [u8],
) -> Result<usize, CryptoError>
where
    C: AeadInPlace + KeyInit + KeySizeUser,
{
    if key.len() != key_len {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonce);
    }
    if ct.len() < TAG_LEN {
        return Err(CryptoError::BadInput);
    }
    let pt_len = ct.len() - TAG_LEN;
    if pt_out.len() < pt_len {
        return Err(CryptoError::BufferTooSmall);
    }

    pt_out[..pt_len].copy_from_slice(&ct[..pt_len]);

    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
    let tag_bytes = &ct[pt_len..];
    let tag = aead::Tag::<C>::clone_from_slice(tag_bytes);

    cipher
        .decrypt_in_place_detached(nonce_arr, aad, &mut pt_out[..pt_len], &tag)
        .map_err(|_| CryptoError::InvalidTag)?;

    Ok(pt_len)
}

// ── AES-128-OCB3 ──────────────────────────────────────────────────────────────

/// AES-128-OCB3 authenticated encryption (RFC 7253).
///
/// Key: 16 bytes, nonce: 12 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128Ocb3;

impl Aead for Aes128Ocb3 {
    fn name(&self) -> &'static str {
        "AES-128-OCB3"
    }

    fn key_len(&self) -> usize {
        Ocb3Aes128::key_size()
    }

    fn nonce_len(&self) -> usize {
        NONCE_LEN
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        ocb3_seal::<Ocb3Aes128>(key, 16, nonce, aad, pt, ct_out)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        ocb3_open::<Ocb3Aes128>(key, 16, nonce, aad, ct, pt_out)
    }
}

// ── AES-256-OCB3 ──────────────────────────────────────────────────────────────

/// AES-256-OCB3 authenticated encryption (RFC 7253).
///
/// Key: 32 bytes, nonce: 12 bytes, tag: 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes256Ocb3;

impl Aead for Aes256Ocb3 {
    fn name(&self) -> &'static str {
        "AES-256-OCB3"
    }

    fn key_len(&self) -> usize {
        Ocb3Aes256::key_size()
    }

    fn nonce_len(&self) -> usize {
        NONCE_LEN
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        ocb3_seal::<Ocb3Aes256>(key, 32, nonce, aad, pt, ct_out)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        ocb3_open::<Ocb3Aes256>(key, 32, nonce, aad, ct, pt_out)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_128: [u8; 16] = [0x42u8; 16];
    const KEY_256: [u8; 32] = [0x42u8; 32];
    const NONCE: [u8; NONCE_LEN] = [0x24u8; NONCE_LEN];
    const AAD: &[u8] = b"additional authenticated data";
    const PLAINTEXT: &[u8] = b"hello, oxicrypto ocb3!";

    #[test]
    fn aes128ocb3_round_trip() {
        let aead = Aes128Ocb3;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_128, &NONCE, AAD, PLAINTEXT, &mut ct)
            .expect("seal failed");
        assert_eq!(written, PLAINTEXT.len() + aead.tag_len());

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let recovered = aead
            .open(&KEY_128, &NONCE, AAD, &ct[..written], &mut pt)
            .expect("open failed");
        assert_eq!(recovered, PLAINTEXT.len());
        assert_eq!(&pt[..recovered], PLAINTEXT);
    }

    #[test]
    fn aes256ocb3_round_trip() {
        let aead = Aes256Ocb3;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_256, &NONCE, AAD, PLAINTEXT, &mut ct)
            .expect("seal failed");
        assert_eq!(written, PLAINTEXT.len() + aead.tag_len());

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let recovered = aead
            .open(&KEY_256, &NONCE, AAD, &ct[..written], &mut pt)
            .expect("open failed");
        assert_eq!(recovered, PLAINTEXT.len());
        assert_eq!(&pt[..recovered], PLAINTEXT);
    }

    #[test]
    fn aes128ocb3_tamper_fails() {
        let aead = Aes128Ocb3;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_128, &NONCE, AAD, PLAINTEXT, &mut ct)
            .unwrap();

        ct[3] ^= 0xFF;

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let result = aead.open(&KEY_128, &NONCE, AAD, &ct[..written], &mut pt);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn aes128ocb3_wrong_key_fails() {
        let aead = Aes128Ocb3;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_128, &NONCE, AAD, PLAINTEXT, &mut ct)
            .unwrap();

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let result = aead.open(&[0u8; 16], &NONCE, AAD, &ct[..written], &mut pt);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }
}
