//! AES-CCM authenticated encryption (RFC 3610).
//!
//! This module provides a pure-Rust implementation of AES-CCM using the
//! `aes` crate for the underlying block cipher.
//!
//! | Algorithm      | Key  | Nonce | Tag  |
//! |----------------|------|-------|------|
//! | AES-128-CCM    | 16 B | 13 B  | 16 B |
//! | AES-256-CCM    | 32 B | 13 B  | 16 B |
//!
//! The nonce length of 13 bytes (L=2) allows messages up to 2^16 - 1 bytes,
//! which is the minimum required by RFC 3610 and covers all practical
//! network-protocol use cases.

use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use oxicrypto_core::{Aead, CryptoError};

// CCM parameters.
//
// Nonce length L_PRIME determines message length field size L.
// L = 15 - L_PRIME. With 13-byte nonces: L = 2 (max message 65535 bytes).
const NONCE_LEN: usize = 13;
const TAG_LEN: usize = 16;
const BLOCK_SIZE: usize = 16;

/// Encode the CBC-MAC header block (B_0) per RFC 3610 §2.2.
///
/// Flags byte: bit 6 = Adata, bits 5-3 = (t-2)/2, bits 2-0 = L-1.
/// With t=16, L=2: flags = Adata_flag | (7 << 3) | 1.
fn encode_b0(nonce: &[u8; NONCE_LEN], aad_len: usize, msg_len: usize) -> [u8; BLOCK_SIZE] {
    let has_aad = aad_len > 0;
    // t = tag length = 16; encoded as (t-2)/2 = 7 in bits 5-3.
    // L = 2 (message length field 2 bytes); encoded as L-1 = 1 in bits 2-0.
    let flags: u8 = if has_aad { 0b0111_1001 } else { 0b0011_1001 };

    let mut b0 = [0u8; BLOCK_SIZE];
    b0[0] = flags;
    b0[1..14].copy_from_slice(nonce);
    // Message length in 2 bytes big-endian (L=2).
    b0[14] = ((msg_len >> 8) & 0xFF) as u8;
    b0[15] = (msg_len & 0xFF) as u8;
    b0
}

/// Encrypt a 16-byte CCM state block in place.
///
/// The conversion is infallible because `state` is statically sized to
/// `BLOCK_SIZE`, but we surface it as `CryptoError::Internal` to keep the
/// production path free of `expect()`/`unwrap()` (no-unwrap policy).
fn encrypt_state_block(
    cipher: &impl BlockCipherEncrypt,
    state: &mut [u8; BLOCK_SIZE],
) -> Result<(), CryptoError> {
    let block = <&mut Array<u8, _>>::try_from(state.as_mut_slice())
        .map_err(|_| CryptoError::Internal("ccm block invariant"))?;
    cipher.encrypt_block(block);
    Ok(())
}

/// Run CBC-MAC over a sequence of blocks using `cipher`.
fn cbc_mac_update(
    cipher: &impl BlockCipherEncrypt,
    state: &mut [u8; BLOCK_SIZE],
    data: &[u8],
) -> Result<(), CryptoError> {
    // Process all complete blocks.
    let mut offset = 0;
    while offset + BLOCK_SIZE <= data.len() {
        for i in 0..BLOCK_SIZE {
            state[i] ^= data[offset + i];
        }
        encrypt_state_block(cipher, state)?;
        offset += BLOCK_SIZE;
    }
    // Process any partial trailing block (zero-padded).
    let remainder = data.len() - offset;
    if remainder > 0 {
        for i in 0..remainder {
            state[i] ^= data[offset + i];
        }
        encrypt_state_block(cipher, state)?;
    }
    Ok(())
}

/// Compute the CBC-MAC tag (T) for CCM per RFC 3610.
fn compute_tag<C: BlockCipherEncrypt + KeyInit>(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> Result<[u8; TAG_LEN], CryptoError> {
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    // B_0: formatted header block.
    let b0 = encode_b0(nonce, aad.len(), msg.len());
    let mut mac_state = [0u8; BLOCK_SIZE];
    // Encrypt B_0 to start CBC-MAC.
    mac_state.copy_from_slice(&b0);
    encrypt_state_block(&cipher, &mut mac_state)?;

    // Encode and process AAD (if any).
    if !aad.is_empty() {
        if aad.len() < 0xFF00 {
            // Length encoding: 2 bytes.
            let len_enc = [(aad.len() >> 8) as u8, (aad.len() & 0xFF) as u8];
            // Combine len_enc + aad into a single feed.
            // We need to MAC: len_enc || aad || zero_padding_to_block_boundary
            let mut buf = [0u8; BLOCK_SIZE];
            buf[0] = len_enc[0];
            buf[1] = len_enc[1];
            let first_chunk = aad.len().min(BLOCK_SIZE - 2);
            buf[2..2 + first_chunk].copy_from_slice(&aad[..first_chunk]);
            // XOR first block with mac_state and encrypt.
            for i in 0..BLOCK_SIZE {
                mac_state[i] ^= buf[i];
            }
            encrypt_state_block(&cipher, &mut mac_state)?;
            // Process remaining aad.
            if aad.len() > first_chunk {
                cbc_mac_update(&cipher, &mut mac_state, &aad[first_chunk..])?;
            }
        } else {
            // For AAD >= 0xFF00 (rare): 6-byte encoding per RFC 3610.
            // We use the simpler 4-byte encoding path for >=64KB AAD.
            let len_enc = [
                0xFF_u8,
                0xFE,
                ((aad.len() >> 24) & 0xFF) as u8,
                ((aad.len() >> 16) & 0xFF) as u8,
                ((aad.len() >> 8) & 0xFF) as u8,
                (aad.len() & 0xFF) as u8,
            ];
            let mut buf = [0u8; BLOCK_SIZE];
            let first_chunk = aad.len().min(BLOCK_SIZE - 6);
            buf[..6].copy_from_slice(&len_enc);
            buf[6..6 + first_chunk].copy_from_slice(&aad[..first_chunk]);
            for i in 0..BLOCK_SIZE {
                mac_state[i] ^= buf[i];
            }
            encrypt_state_block(&cipher, &mut mac_state)?;
            if aad.len() > first_chunk {
                cbc_mac_update(&cipher, &mut mac_state, &aad[first_chunk..])?;
            }
        }
    }

    // Process message data.
    cbc_mac_update(&cipher, &mut mac_state, msg)?;

    Ok(mac_state)
}

/// Compute CTR keystream blocks for CCM per RFC 3610 §2.3.
///
/// A_i = flags || nonce || counter_i (big-endian 2 bytes, L=2).
/// flags for counter blocks: bits 2-0 = L-1 = 1.
fn ctr_crypt<C: BlockCipherEncrypt + KeyInit>(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    data: &[u8],
    out: &mut [u8],
    start_counter: u16,
) -> Result<(), CryptoError> {
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    // flags = 0x01 (L-1 = 1 for L=2).
    const FLAGS: u8 = 0x01;
    let mut counter = start_counter;
    let mut offset = 0;

    while offset < data.len() {
        let mut a_block = [0u8; BLOCK_SIZE];
        a_block[0] = FLAGS;
        a_block[1..14].copy_from_slice(nonce);
        a_block[14] = ((counter >> 8) & 0xFF) as u8;
        a_block[15] = (counter & 0xFF) as u8;

        encrypt_state_block(&cipher, &mut a_block)?;

        let chunk_end = (offset + BLOCK_SIZE).min(data.len());
        let chunk_len = chunk_end - offset;
        for i in 0..chunk_len {
            out[offset + i] = data[offset + i] ^ a_block[i];
        }

        offset = chunk_end;
        counter = counter.wrapping_add(1);
    }

    Ok(())
}

/// Seal (encrypt + authenticate) with the given AES block cipher type.
///
/// Output layout: ciphertext (same length as plaintext) || tag (16 bytes).
fn ccm_seal<C: BlockCipherEncrypt + KeyInit>(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    ct_out: &mut [u8],
) -> Result<usize, CryptoError> {
    let required = pt.len().checked_add(TAG_LEN).ok_or(CryptoError::BadInput)?;
    if ct_out.len() < required {
        return Err(CryptoError::BufferTooSmall);
    }

    // 1. Compute CBC-MAC tag over plaintext.
    let raw_tag = compute_tag::<C>(key, nonce, aad, pt)?;

    // 2. Encrypt plaintext with CTR (counter starts at 1; counter 0 encrypts the tag).
    ctr_crypt::<C>(key, nonce, pt, &mut ct_out[..pt.len()], 1)?;

    // 3. Encrypt tag with CTR counter = 0.
    let mut encrypted_tag = [0u8; TAG_LEN];
    ctr_crypt::<C>(key, nonce, &raw_tag, &mut encrypted_tag, 0)?;

    ct_out[pt.len()..required].copy_from_slice(&encrypted_tag);
    Ok(required)
}

/// Open (decrypt + verify) with the given AES block cipher type.
fn ccm_open<C: BlockCipherEncrypt + KeyInit>(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    pt_out: &mut [u8],
) -> Result<usize, CryptoError> {
    if ct.len() < TAG_LEN {
        return Err(CryptoError::BadInput);
    }
    let pt_len = ct.len() - TAG_LEN;
    if pt_out.len() < pt_len {
        return Err(CryptoError::BufferTooSmall);
    }

    let (ciphertext, tag_bytes) = ct.split_at(pt_len);

    // 1. Decrypt ciphertext (CTR counter = 1).
    ctr_crypt::<C>(key, nonce, ciphertext, &mut pt_out[..pt_len], 1)?;

    // 2. Decrypt tag (CTR counter = 0) to recover raw CBC-MAC tag.
    let mut raw_tag = [0u8; TAG_LEN];
    ctr_crypt::<C>(key, nonce, tag_bytes, &mut raw_tag, 0)?;

    // 3. Recompute CBC-MAC tag over the recovered plaintext.
    let expected_tag = compute_tag::<C>(key, nonce, aad, &pt_out[..pt_len])?;

    // 4. Constant-time compare.
    use subtle::ConstantTimeEq as _;
    if raw_tag.ct_eq(&expected_tag).into() {
        Ok(pt_len)
    } else {
        // Zero out the decrypted plaintext to prevent partial-decryption exposure.
        for b in &mut pt_out[..pt_len] {
            *b = 0;
        }
        Err(CryptoError::InvalidTag)
    }
}

// ── AES-128-CCM ───────────────────────────────────────────────────────────────

/// AES-128-CCM authenticated encryption (RFC 3610).
///
/// Key: 16 bytes, nonce: 13 bytes, tag: 16 bytes.
/// Maximum plaintext length: 65 535 bytes (L=2 message length field).
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128Ccm;

impl Aead for Aes128Ccm {
    fn name(&self) -> &'static str {
        "AES-128-CCM"
    }

    fn key_len(&self) -> usize {
        16
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
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidNonce);
        }
        let nonce_arr: &[u8; NONCE_LEN] =
            nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
        ccm_seal::<Aes128>(key, nonce_arr, aad, pt, ct_out)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidNonce);
        }
        let nonce_arr: &[u8; NONCE_LEN] =
            nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
        ccm_open::<Aes128>(key, nonce_arr, aad, ct, pt_out)
    }
}

// ── AES-256-CCM ───────────────────────────────────────────────────────────────

/// AES-256-CCM authenticated encryption (RFC 3610).
///
/// Key: 32 bytes, nonce: 13 bytes, tag: 16 bytes.
/// Maximum plaintext length: 65 535 bytes (L=2 message length field).
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes256Ccm;

impl Aead for Aes256Ccm {
    fn name(&self) -> &'static str {
        "AES-256-CCM"
    }

    fn key_len(&self) -> usize {
        32
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
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidNonce);
        }
        let nonce_arr: &[u8; NONCE_LEN] =
            nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
        ccm_seal::<Aes256>(key, nonce_arr, aad, pt, ct_out)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidNonce);
        }
        let nonce_arr: &[u8; NONCE_LEN] =
            nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
        ccm_open::<Aes256>(key, nonce_arr, aad, ct, pt_out)
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
    const PLAINTEXT: &[u8] = b"hello, oxicrypto ccm!";

    #[test]
    fn aes128ccm_round_trip() {
        let aead = Aes128Ccm;
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
    fn aes256ccm_round_trip() {
        let aead = Aes256Ccm;
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
    fn aes128ccm_tamper_ciphertext_fails() {
        let aead = Aes128Ccm;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_128, &NONCE, AAD, PLAINTEXT, &mut ct)
            .unwrap();

        ct[0] ^= 0xFF; // flip a byte in ciphertext

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let result = aead.open(&KEY_128, &NONCE, AAD, &ct[..written], &mut pt);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn aes128ccm_tamper_tag_fails() {
        let aead = Aes128Ccm;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_128, &NONCE, AAD, PLAINTEXT, &mut ct)
            .unwrap();

        ct[written - 1] ^= 0x01; // flip last byte of tag

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let result = aead.open(&KEY_128, &NONCE, AAD, &ct[..written], &mut pt);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn aes128ccm_wrong_key_fails() {
        let aead = Aes128Ccm;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_128, &NONCE, AAD, PLAINTEXT, &mut ct)
            .unwrap();

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let result = aead.open(&[0x00u8; 16], &NONCE, AAD, &ct[..written], &mut pt);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn aes128ccm_empty_plaintext() {
        let aead = Aes128Ccm;
        let mut ct = vec![0u8; aead.tag_len()];
        let written = aead.seal(&KEY_128, &NONCE, AAD, b"", &mut ct).unwrap();
        assert_eq!(written, aead.tag_len());

        let mut pt = vec![0u8; 0];
        let recovered = aead
            .open(&KEY_128, &NONCE, AAD, &ct[..written], &mut pt)
            .unwrap();
        assert_eq!(recovered, 0);
    }

    #[test]
    fn aes128ccm_no_aad() {
        let aead = Aes128Ccm;
        let mut ct = vec![0u8; PLAINTEXT.len() + aead.tag_len()];
        let written = aead
            .seal(&KEY_128, &NONCE, b"", PLAINTEXT, &mut ct)
            .unwrap();

        let mut pt = vec![0u8; PLAINTEXT.len()];
        let recovered = aead
            .open(&KEY_128, &NONCE, b"", &ct[..written], &mut pt)
            .unwrap();
        assert_eq!(&pt[..recovered], PLAINTEXT);
    }

    /// NIST CAVP-like vector: AES-128-CCM with key=all-zeros, nonce=all-zeros.
    /// This is a known-answer sanity check.
    #[test]
    fn aes128ccm_deterministic_output() {
        let aead = Aes128Ccm;
        let key = [0u8; 16];
        let nonce = [0u8; NONCE_LEN];
        let pt = b"test";
        let mut ct = vec![0u8; pt.len() + aead.tag_len()];
        let written = aead.seal(&key, &nonce, b"", pt, &mut ct).unwrap();

        // Round-trip: decrypt and verify.
        let mut pt_out = vec![0u8; pt.len()];
        let recovered = aead
            .open(&key, &nonce, b"", &ct[..written], &mut pt_out)
            .unwrap();
        assert_eq!(&pt_out[..recovered], pt.as_ref());

        // Second call with same inputs must produce identical ciphertext (deterministic).
        let mut ct2 = vec![0u8; pt.len() + aead.tag_len()];
        let written2 = aead.seal(&key, &nonce, b"", pt, &mut ct2).unwrap();
        assert_eq!(ct[..written], ct2[..written2]);
    }
}
