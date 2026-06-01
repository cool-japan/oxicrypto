#![forbid(unsafe_code)]

//! Deoxys-II-128-128 authenticated encryption (SCT-2 mode).
//!
//! Deoxys-II is the **nonce-misuse-resistant** member of the Deoxys AEAD
//! family and was selected as the first choice in the final CAESAR portfolio
//! for the "defense in depth" use case. It is built on the
//! the Deoxys-BC-256 tweakable block cipher run in the SCT-2
//! (Synthetic Counter in Tweak, variant 2) mode of operation.
//!
//! | Parameter | Value |
//! |-----------|-------|
//! | Key       | 16 bytes |
//! | Nonce     | 16 bytes (only the leading 120 bits enter the tweak, per the Deoxys-II-128 spec) |
//! | Tag       | 16 bytes |
//!
//! # Misuse resistance
//!
//! SCT-2 is a two-pass, SIV-style construction: the tag is a
//! pseudo-random function of the *entire* (nonce, AD, message), and that tag
//! then seeds the counter-mode keystream. Consequently, reusing a nonce with
//! two different messages leaks **only** whether the two messages were equal —
//! it does not expose the keystream the way a nonce collision does for
//! AES-GCM or ChaCha20-Poly1305.
//!
//! # Mode definition (Deoxys v1.43, Algorithms 5 & 6)
//!
//! With 4-bit tweak-domain prefixes packed into the top nibble of tweak
//! byte 0 and a 64-bit big-endian block counter in tweak bytes 8..16:
//!
//! * **Auth pass** — `Auth = 0`; absorb each full AD block with prefix `0x20`
//!   and a padded final AD block with prefix `0x60`; absorb each full message
//!   block with prefix `0x00` and a padded final message block with prefix
//!   `0x40`, XOR-accumulating the block-cipher outputs into `Auth`. Partial
//!   final blocks use `10*` padding (append `0x80`, then zeros).
//! * **Tag** — `tag = E_K(0x10 ‖ nonce[..15], Auth)`.
//! * **Encrypt pass** — for block `j`, keystream `= E_K(tweak_j, 0x00 ‖ nonce[..15])`
//!   where `tweak_j = (tag with MSB forced to 1) ⊕ (j as 64-bit BE in bytes 8..16)`;
//!   `C_j = M_j ⊕ keystream`. Output is `C ‖ tag`.
//!
//! Decryption recomputes the keystream from the received tag, re-runs the auth
//! pass over the recovered plaintext, and verifies the tag in constant time
//! ([`oxicrypto_core::ct_eq`]).

use crate::deoxys_bc::{DeoxysBc256, BLOCK_SIZE};
use oxicrypto_core::{ct_eq, Aead, CryptoError};

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
/// Number of nonce bytes that enter the tweak (120-bit nonce of Deoxys-II-128).
const NONCE_TWEAK_LEN: usize = 15;

// Tweak-domain prefixes (top nibble of tweak byte 0).
const TWEAK_AD: u8 = 0x20;
const TWEAK_AD_LAST: u8 = 0x60;
const TWEAK_MSG: u8 = 0x00;
const TWEAK_MSG_LAST: u8 = 0x40;
const TWEAK_TAG: u8 = 0x10;

/// Write the 64-bit big-endian block counter into tweak bytes 8..16.
#[inline]
fn set_counter(tweak: &mut [u8; BLOCK_SIZE], index: u64) {
    tweak[8..16].copy_from_slice(&index.to_be_bytes());
}

/// Absorb the associated data into the running `auth` accumulator.
fn absorb_ad(bc: &DeoxysBc256, aad: &[u8], auth: &mut [u8; BLOCK_SIZE]) {
    if aad.is_empty() {
        return;
    }
    let mut tweak = [0u8; BLOCK_SIZE];
    let full_blocks = aad.len() / BLOCK_SIZE;
    let rem = aad.len() % BLOCK_SIZE;

    for (index, chunk) in aad.chunks(BLOCK_SIZE).take(full_blocks).enumerate() {
        tweak[0] = TWEAK_AD;
        set_counter(&mut tweak, index as u64);
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        let out = bc.encrypt_block(&tweak, &block);
        xor_into(auth, &out);
    }

    if rem != 0 {
        tweak[0] = TWEAK_AD_LAST;
        set_counter(&mut tweak, full_blocks as u64);
        let mut block = [0u8; BLOCK_SIZE];
        block[..rem].copy_from_slice(&aad[full_blocks * BLOCK_SIZE..]);
        block[rem] = 0x80; // 10* padding
        let out = bc.encrypt_block(&tweak, &block);
        xor_into(auth, &out);
    }
}

/// Absorb the message into the running `auth` accumulator (authentication pass).
fn absorb_message(bc: &DeoxysBc256, msg: &[u8], auth: &mut [u8; BLOCK_SIZE]) {
    if msg.is_empty() {
        return;
    }
    let mut tweak = [0u8; BLOCK_SIZE];
    let full_blocks = msg.len() / BLOCK_SIZE;
    let rem = msg.len() % BLOCK_SIZE;

    for (index, chunk) in msg.chunks(BLOCK_SIZE).take(full_blocks).enumerate() {
        tweak[0] = TWEAK_MSG;
        set_counter(&mut tweak, index as u64);
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        let out = bc.encrypt_block(&tweak, &block);
        xor_into(auth, &out);
    }

    if rem != 0 {
        tweak[0] = TWEAK_MSG_LAST;
        set_counter(&mut tweak, full_blocks as u64);
        let mut block = [0u8; BLOCK_SIZE];
        block[..rem].copy_from_slice(&msg[full_blocks * BLOCK_SIZE..]);
        block[rem] = 0x80; // 10* padding
        let out = bc.encrypt_block(&tweak, &block);
        xor_into(auth, &out);
    }
}

/// Compute the authentication tag over (AD, message) and nonce.
fn compute_tag(bc: &DeoxysBc256, nonce: &[u8], aad: &[u8], msg: &[u8]) -> [u8; TAG_LEN] {
    let mut auth = [0u8; BLOCK_SIZE];
    absorb_ad(bc, aad, &mut auth);
    absorb_message(bc, msg, &mut auth);

    // tag = E_K(0x10 ‖ nonce[..15], Auth)
    let mut tweak = [0u8; BLOCK_SIZE];
    tweak[0] = TWEAK_TAG;
    tweak[1..1 + NONCE_TWEAK_LEN].copy_from_slice(&nonce[..NONCE_TWEAK_LEN]);
    bc.encrypt_block(&tweak, &auth)
}

/// Apply the SCT-2 counter-mode keystream to `data` in place (encrypt or
/// decrypt — the operation is symmetric).
///
/// For block `j`, keystream `= E_K(tweak_j, 0x00 ‖ nonce[..15])` with
/// `tweak_j = tag_masked ⊕ (j in bytes 8..16)`, where `tag_masked` is the tag
/// with its most-significant bit forced to 1.
fn apply_keystream(bc: &DeoxysBc256, nonce: &[u8], tag: &[u8; TAG_LEN], data: &mut [u8]) {
    if data.is_empty() {
        return;
    }

    // Base tweak = tag with MSB of byte 0 set to 1.
    let mut base = [0u8; BLOCK_SIZE];
    base.copy_from_slice(tag);
    base[0] |= 0x80;

    // The cipher input for every keystream block is 0x00 ‖ nonce[..15].
    let mut input = [0u8; BLOCK_SIZE];
    input[1..1 + NONCE_TWEAK_LEN].copy_from_slice(&nonce[..NONCE_TWEAK_LEN]);

    for (index, chunk) in data.chunks_mut(BLOCK_SIZE).enumerate() {
        let mut tweak = base;
        // XOR the 64-bit block counter into bytes 8..16.
        let ctr = (index as u64).to_be_bytes();
        for (t, c) in tweak[8..16].iter_mut().zip(ctr.iter()) {
            *t ^= c;
        }
        let keystream = bc.encrypt_block(&tweak, &input);
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
            *b ^= k;
        }
    }
}

/// XOR a 16-byte block into an accumulator.
#[inline]
fn xor_into(acc: &mut [u8; BLOCK_SIZE], block: &[u8; BLOCK_SIZE]) {
    for (a, b) in acc.iter_mut().zip(block.iter()) {
        *a ^= b;
    }
}

/// Deoxys-II-128-128 authenticated encryption (nonce-misuse resistant).
///
/// Key: 16 bytes, nonce: 16 bytes, tag: 16 bytes. Implements the
/// [`oxicrypto_core::Aead`] trait; output layout of `seal` is
/// `ciphertext ‖ tag`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Deoxys2_128;

impl Deoxys2_128 {
    /// Seal `pt` into `ct_out` (= ciphertext ‖ tag).
    fn seal_impl(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if key.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidNonce);
        }
        let required = pt.len().checked_add(TAG_LEN).ok_or(CryptoError::BadInput)?;
        if ct_out.len() < required {
            return Err(CryptoError::BufferTooSmall);
        }

        let mut key_arr = [0u8; KEY_LEN];
        key_arr.copy_from_slice(key);
        let bc = DeoxysBc256::new(&key_arr);

        // Pass 1: authenticate (AD ‖ plaintext) and derive the tag.
        let tag = compute_tag(&bc, nonce, aad, pt);

        // Pass 2: counter-mode encrypt the plaintext.
        ct_out[..pt.len()].copy_from_slice(pt);
        apply_keystream(&bc, nonce, &tag, &mut ct_out[..pt.len()]);

        // Append the tag.
        ct_out[pt.len()..required].copy_from_slice(&tag);
        Ok(required)
    }

    /// Open `ct` (= ciphertext ‖ tag) into `pt_out`.
    fn open_impl(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if key.len() != KEY_LEN {
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

        let mut key_arr = [0u8; KEY_LEN];
        key_arr.copy_from_slice(key);
        let bc = DeoxysBc256::new(&key_arr);

        let (ciphertext, received_tag) = ct.split_at(pt_len);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(received_tag);

        // Pass 1: recompute the keystream from the received tag and decrypt.
        pt_out[..pt_len].copy_from_slice(ciphertext);
        apply_keystream(&bc, nonce, &tag, &mut pt_out[..pt_len]);

        // Pass 2: re-authenticate the recovered plaintext and regenerate the tag.
        let expected = compute_tag(&bc, nonce, aad, &pt_out[..pt_len]);

        // Constant-time tag comparison.
        if ct_eq(&expected, &tag) {
            Ok(pt_len)
        } else {
            // Wipe the tentatively-decrypted plaintext on failure.
            for b in &mut pt_out[..pt_len] {
                *b = 0;
            }
            Err(CryptoError::InvalidTag)
        }
    }
}

impl Aead for Deoxys2_128 {
    fn name(&self) -> &'static str {
        "Deoxys-II-128-128"
    }
    fn key_len(&self) -> usize {
        KEY_LEN
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
        Self::seal_impl(key, nonce, aad, pt, ct_out)
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Self::open_impl(key, nonce, aad, ct, pt_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const NONCE: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];

    #[test]
    fn round_trip_multiblock() {
        let aead = Deoxys2_128;
        let pt = b"The quick brown fox jumps over the lazy dog!! Deoxys-II misuse resistant.";
        let aad = b"header-metadata";
        let mut ct = vec![0u8; pt.len() + aead.tag_len()];
        let written = aead.seal(&KEY, &NONCE, aad, pt, &mut ct).expect("seal");
        assert_eq!(written, pt.len() + 16);

        let mut dec = vec![0u8; pt.len()];
        let n = aead
            .open(&KEY, &NONCE, aad, &ct[..written], &mut dec)
            .expect("open");
        assert_eq!(&dec[..n], pt.as_ref());
    }

    #[test]
    fn empty_message_empty_aad() {
        let aead = Deoxys2_128;
        let mut ct = vec![0u8; aead.tag_len()];
        let written = aead.seal(&KEY, &NONCE, b"", b"", &mut ct).expect("seal");
        assert_eq!(written, 16);
        let mut dec = vec![0u8; 0];
        assert_eq!(
            aead.open(&KEY, &NONCE, b"", &ct[..written], &mut dec)
                .expect("open"),
            0
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let aead = Deoxys2_128;
        let pt = b"secret";
        let mut ct = vec![0u8; pt.len() + 16];
        let written = aead.seal(&KEY, &NONCE, b"", pt, &mut ct).expect("seal");
        let mut dec = vec![0u8; pt.len()];
        assert_eq!(
            aead.open(&[0u8; 16], &NONCE, b"", &ct[..written], &mut dec),
            Err(CryptoError::InvalidTag)
        );
    }

    #[test]
    fn invalid_lengths() {
        let aead = Deoxys2_128;
        let mut ct = vec![0u8; 32];
        assert_eq!(
            aead.seal(&[0u8; 15], &NONCE, b"", b"x", &mut ct),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(
            aead.seal(&KEY, &[0u8; 12], b"", b"x", &mut ct),
            Err(CryptoError::InvalidNonce)
        );
    }
}
