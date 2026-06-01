#![forbid(unsafe_code)]

//! Raw single-block / stream cipher primitives for the OxiCrypto stack.
//!
//! These are deliberately *low-level* building blocks, distinct from the
//! authenticated [`oxicrypto-aead`](https://docs.rs/oxicrypto-aead) ciphers.
//! They exist for QUIC header protection (RFC 9001 §5.4), which masks packet
//! headers with a 5-byte sample of either an AES-ECB single-block encryption
//! (§5.4.3) or a ChaCha20 keystream block (§5.4.4).
//!
//! | Primitive | Function | Notes |
//! |-----------|----------|-------|
//! | AES-128 single block | [`aes128_encrypt_block`] | one 16-byte ECB block |
//! | AES-256 single block | [`aes256_encrypt_block`] | one 16-byte ECB block |
//! | ChaCha20 keystream block | [`chacha20_keystream_block`] | RFC 8439 / RFC 9001 §5.4.4 |
//!
//! All wrappers are `#![forbid(unsafe_code)]`; the underlying `aes` / `chacha20`
//! crates provide safe constructors (`KeyInit::new`, `KeyIvInit::new`) and
//! operations (`BlockEncrypt::encrypt_block`, `StreamCipher::apply_keystream`).

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use oxicrypto_core::CryptoError;

/// AES block size in bytes.
pub const AES_BLOCK_LEN: usize = 16;

/// AES-128 key length in bytes.
pub const AES128_KEY_LEN: usize = 16;

/// AES-256 key length in bytes.
pub const AES256_KEY_LEN: usize = 32;

/// Encrypt a single 16-byte block with AES-128 in raw ECB mode.
///
/// This is the QUIC header-protection mask primitive for the AES-128 suite
/// (RFC 9001 §5.4.3): `mask = AES-ECB(hp_key, sample)`.
///
/// `key` must be exactly 16 bytes; `block` must be exactly 16 bytes. The
/// ciphertext block is written into `out` (16 bytes).
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `key` is not 16 bytes,
/// [`CryptoError::BadInput`] if `block` is not 16 bytes, and
/// [`CryptoError::BufferTooSmall`] if `out` is shorter than 16 bytes.
pub fn aes128_encrypt_block(key: &[u8], block: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if key.len() != AES128_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if block.len() != AES_BLOCK_LEN {
        return Err(CryptoError::BadInput);
    }
    if out.len() < AES_BLOCK_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Aes128::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let mut buf: aes::Block = aes::Block::try_from(block).map_err(|_| CryptoError::BadInput)?;
    cipher.encrypt_block(&mut buf);
    out[..AES_BLOCK_LEN].copy_from_slice(&buf);
    Ok(())
}

/// Encrypt a single 16-byte block with AES-256 in raw ECB mode.
///
/// QUIC header-protection mask primitive for the AES-256 suite
/// (RFC 9001 §5.4.3). `key` must be exactly 32 bytes; `block` and `out` are
/// 16 bytes as for [`aes128_encrypt_block`].
///
/// # Errors
/// As [`aes128_encrypt_block`], but `key` must be 32 bytes.
pub fn aes256_encrypt_block(key: &[u8], block: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if key.len() != AES256_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if block.len() != AES_BLOCK_LEN {
        return Err(CryptoError::BadInput);
    }
    if out.len() < AES_BLOCK_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Aes256::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let mut buf: aes::Block = aes::Block::try_from(block).map_err(|_| CryptoError::BadInput)?;
    cipher.encrypt_block(&mut buf);
    out[..AES_BLOCK_LEN].copy_from_slice(&buf);
    Ok(())
}

/// ChaCha20 key length in bytes.
pub const CHACHA20_KEY_LEN: usize = 32;

/// ChaCha20 nonce length in bytes (IETF / RFC 8439 variant).
pub const CHACHA20_NONCE_LEN: usize = 12;

/// Produce ChaCha20 keystream bytes for a given 32-byte key, 32-bit block
/// counter, and 12-byte nonce (RFC 8439 / RFC 9001 §5.4.4).
///
/// The keystream is generated starting at block `counter` and XORed against an
/// all-zero buffer, so `out` is filled with raw keystream. For QUIC header
/// protection the caller passes `counter` taken from the first 4 bytes of the
/// header-protection sample (little-endian), the nonce from the remaining 12
/// sample bytes, and a 5-byte `out` buffer to receive the mask.
///
/// `out` may be any length up to one ChaCha20 keystream block beyond the
/// counter that does not overflow the 32-bit counter; for QUIC it is 5 bytes.
///
/// # Errors
/// Returns [`CryptoError::InvalidKey`] if `key` is not 32 bytes,
/// [`CryptoError::InvalidNonce`] if `nonce` is not 12 bytes, and
/// [`CryptoError::BadInput`] if `out` is empty.
pub fn chacha20_keystream_block(
    key: &[u8],
    counter: u32,
    nonce: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if key.len() != CHACHA20_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != CHACHA20_NONCE_LEN {
        return Err(CryptoError::InvalidNonce);
    }
    if out.is_empty() {
        return Err(CryptoError::BadInput);
    }

    let key_arr: chacha20::Key =
        chacha20::Key::try_from(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce_arr: chacha20::cipher::Iv<ChaCha20> =
        chacha20::cipher::Iv::<ChaCha20>::try_from(nonce).map_err(|_| CryptoError::InvalidNonce)?;
    let mut cipher = ChaCha20::new(&key_arr, &nonce_arr);
    // Seek to the requested 32-bit block counter (counter * 64 bytes).
    let byte_offset = u64::from(counter)
        .checked_mul(64)
        .ok_or(CryptoError::BadInput)?;
    cipher.seek(byte_offset);
    // Zero the output then XOR keystream over it -> raw keystream.
    for b in out.iter_mut() {
        *b = 0;
    }
    cipher.apply_keystream(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // FIPS-197 AES-128 known-answer: key = 000102...0f, pt = 00112233...ff,
    // ct = 69c4e0d86a7b0430d8cdb78070b4c55a.
    #[test]
    fn aes128_fips197_appendix_b() {
        let key = hex_decode("000102030405060708090a0b0c0d0e0f");
        let pt = hex_decode("00112233445566778899aabbccddeeff");
        let mut out = [0u8; 16];
        aes128_encrypt_block(&key, &pt, &mut out).expect("aes128");
        assert_eq!(out.to_vec(), hex_decode("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    // FIPS-197 AES-256 known-answer: key = 0001...1f, pt = 00112233...ff,
    // ct = 8ea2b7ca516745bfeafc49904b496089.
    #[test]
    fn aes256_fips197_appendix_c() {
        let key = hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex_decode("00112233445566778899aabbccddeeff");
        let mut out = [0u8; 16];
        aes256_encrypt_block(&key, &pt, &mut out).expect("aes256");
        assert_eq!(out.to_vec(), hex_decode("8ea2b7ca516745bfeafc49904b496089"));
    }

    // RFC 9001 §A.5: ChaCha20 header protection sample.
    // hp key = 25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4
    // sample = 5e5cd55c41f69080575d7999c25a5bfb
    //   counter = 0x5e5cd55c (LE of first 4 bytes) ... actually sample[0..4]
    //             interpreted little-endian.
    //   nonce   = sample[4..16]
    // mask    = aefefe7d03  (first 5 bytes of keystream)
    #[test]
    fn rfc9001_a5_chacha20_header_mask() {
        let hp = hex_decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let sample = hex_decode("5e5cd55c41f69080575d7999c25a5bfb");
        // counter from first 4 bytes, little-endian
        let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
        let nonce = &sample[4..16];
        let mut mask = [0u8; 5];
        chacha20_keystream_block(&hp, counter, nonce, &mut mask).expect("ks");
        assert_eq!(
            mask.to_vec(),
            hex_decode("aefefe7d03"),
            "RFC 9001 A.5 mask mismatch"
        );
    }

    #[test]
    fn aes_invalid_lengths() {
        let mut out = [0u8; 16];
        assert_eq!(
            aes128_encrypt_block(&[0u8; 15], &[0u8; 16], &mut out),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(
            aes128_encrypt_block(&[0u8; 16], &[0u8; 15], &mut out),
            Err(CryptoError::BadInput)
        );
        assert_eq!(
            aes256_encrypt_block(&[0u8; 32], &[0u8; 16], &mut [0u8; 8]),
            Err(CryptoError::BufferTooSmall)
        );
    }

    #[test]
    fn chacha20_invalid_lengths() {
        let mut out = [0u8; 5];
        assert_eq!(
            chacha20_keystream_block(&[0u8; 31], 0, &[0u8; 12], &mut out),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(
            chacha20_keystream_block(&[0u8; 32], 0, &[0u8; 11], &mut out),
            Err(CryptoError::InvalidNonce)
        );
        assert_eq!(
            chacha20_keystream_block(&[0u8; 32], 0, &[0u8; 12], &mut []),
            Err(CryptoError::BadInput)
        );
    }

    // RFC 8439 §2.4.2 keystream sanity (block counter 1, the documented test
    // vector starts at counter=1): verify determinism + non-zero output.
    #[test]
    fn chacha20_keystream_deterministic() {
        let key = [0x01u8; 32];
        let nonce = [0x02u8; 12];
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        chacha20_keystream_block(&key, 1, &nonce, &mut a).expect("a");
        chacha20_keystream_block(&key, 1, &nonce, &mut b).expect("b");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 16]);
    }
}
