#![forbid(unsafe_code)]

//! Deoxys-BC-256 tweakable block cipher (forward direction).
//!
//! Deoxys-BC is the AES-based tweakable block cipher underlying the Deoxys
//! AEAD family (CAESAR final portfolio). This module implements the
//! **Deoxys-BC-256** instance: a 128-bit block, a 256-bit *tweakey* split into
//! a 128-bit key (`TK2`) and a 128-bit tweak (`TK1`), and 14 rounds.
//!
//! Only the forward (encryption) direction is implemented, because the
//! Deoxys-II SCT-2 mode never needs the inverse cipher: decryption recomputes
//! the keystream in counter mode (forward cipher) and re-runs the forward
//! authentication pass (see [`crate::deoxys`]).
//!
//! The round function reuses the pure-Rust `aes::hazmat::cipher_round`, which
//! computes `AddRoundKey ∘ MixColumns ∘ ShiftRows ∘ SubBytes` — exactly one
//! Deoxys-BC round (every round, including the last, retains MixColumns).
//!
//! ## Tweakey schedule (Deoxys v1.43 spec)
//!
//! For round `i`, the subtweakey is `STK_i = TK1_i ⊕ TK2_i ⊕ RC_i` where:
//! * `TK1_{i+1} = h(TK1_i)` (byte permutation `h`),
//! * `TK2_{i+1} = h(LFSR2(TK2_i))`,
//! * `RC_i` is the round constant `[1,2,4,8, RCON[i]×4, 0×8]` (column-major).
//!
//! Following the standard reference factoring, the key-dependent part
//! (`TK2_i ⊕ RC_i`) is precomputed once per key, and the tweak-dependent part
//! (`h^i(TK1)`) is folded in per block.

use aes::hazmat::cipher_round;
use aes::Block;

/// Block size in bytes (128 bits).
pub(crate) const BLOCK_SIZE: usize = 16;

/// Number of rounds for Deoxys-BC-256.
const ROUNDS: usize = 14;

/// Number of subtweakeys (= ROUNDS + 1: initial whitening + one per round).
const SUBKEYS: usize = ROUNDS + 1;

/// The byte permutation `h` of the Deoxys tweakey schedule.
///
/// Applied as `out[i] = in[H_PERM[i]]`. Taken verbatim from the Deoxys
/// specification (the SKINNY/Deoxys nibble/byte permutation).
const H_PERM: [usize; 16] = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8];

/// `RCON[i]` constants of the Deoxys tweakey schedule (spec Table 18).
///
/// These are the `i + 15`-th AES key-schedule constants. Index 0 is used for
/// the whitening subtweakey, indices 1..=14 for the 14 rounds.
const RCON: [u8; SUBKEYS] = [
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
];

/// Apply the byte permutation `h` to a 128-bit tweakey word in place.
fn h_permute(tk: &mut [u8; BLOCK_SIZE]) {
    let mut out = [0u8; BLOCK_SIZE];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = tk[H_PERM[i]];
    }
    *tk = out;
}

/// Apply `LFSR2` to each byte of a 128-bit tweakey word in place.
///
/// `LFSR2`: `(x7 x6 x5 x4 x3 x2 x1 x0) → (x6 x5 x4 x3 x2 x1 x0, x7 ⊕ x5)`,
/// i.e. a left shift whose new LSB is `bit7 ⊕ bit5`.
fn lfsr2(tk: &mut [u8; BLOCK_SIZE]) {
    for b in tk.iter_mut() {
        let new_lsb = ((*b >> 7) ^ (*b >> 5)) & 0x01;
        *b = (*b << 1) | new_lsb;
    }
}

/// Build the round-constant word `RC_i` (column-major byte layout).
///
/// `RC_i` = column 0 `[1,2,4,8]` (bytes 0..4), column 1 `[RCON,RCON,RCON,RCON]`
/// (bytes 4..8), columns 2,3 all zero.
fn round_constant(i: usize) -> [u8; BLOCK_SIZE] {
    let rc = RCON[i];
    [1, 2, 4, 8, rc, rc, rc, rc, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// Pre-expanded key schedule for Deoxys-BC-256.
///
/// Holds the key-only contribution to each subtweakey, namely
/// `key_sub[i] = TK2_i ⊕ RC_i`, where `TK2_0 = key` and
/// `TK2_{i+1} = h(LFSR2(TK2_i))`. The tweak contribution is added per block in
/// [`DeoxysBc256::encrypt_block`].
#[derive(Clone)]
pub(crate) struct DeoxysBc256 {
    key_sub: [[u8; BLOCK_SIZE]; SUBKEYS],
}

impl DeoxysBc256 {
    /// Precompute the key-dependent subtweakey contributions for `key`.
    pub(crate) fn new(key: &[u8; BLOCK_SIZE]) -> Self {
        let mut key_sub = [[0u8; BLOCK_SIZE]; SUBKEYS];
        let mut tk2 = *key;

        // Whitening subtweakey: TK2_0 ⊕ RC_0.
        let rc0 = round_constant(0);
        for i in 0..BLOCK_SIZE {
            key_sub[0][i] = tk2[i] ^ rc0[i];
        }

        // Remaining subtweakeys: advance TK2 via h ∘ LFSR2 each round.
        for (round, slot) in key_sub.iter_mut().enumerate().skip(1) {
            h_permute(&mut tk2);
            lfsr2(&mut tk2);
            let rc = round_constant(round);
            for i in 0..BLOCK_SIZE {
                slot[i] = tk2[i] ^ rc[i];
            }
        }

        Self { key_sub }
    }

    /// Encrypt a single 128-bit block under the given 128-bit `tweak`.
    ///
    /// Computes `C = E_K(tweak, plaintext)` for Deoxys-BC-256. The full
    /// subtweakey for round `i` is `key_sub[i] ⊕ h^i(tweak)`.
    pub(crate) fn encrypt_block(
        &self,
        tweak: &[u8; BLOCK_SIZE],
        plaintext: &[u8; BLOCK_SIZE],
    ) -> [u8; BLOCK_SIZE] {
        let mut tk1 = *tweak;

        // Initial AddRoundTweakey with the whitening subtweakey STK_0.
        let mut state = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            state[i] = plaintext[i] ^ self.key_sub[0][i] ^ tk1[i];
        }
        let mut block = Block::from(state);

        // 14 rounds: cipher_round = SubBytes → ShiftRows → MixColumns →
        // AddRoundKey(STK_r).
        for round in 1..=ROUNDS {
            h_permute(&mut tk1);
            let mut stk = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                stk[i] = self.key_sub[round][i] ^ tk1[i];
            }
            cipher_round(&mut block, &Block::from(stk));
        }

        block.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standalone Deoxys-BC-256 single-block known-answer test.
    ///
    /// This vector is the tag-generation block-cipher call of the official
    /// Deoxys-II-128 test vector #1 (empty AD, empty message): the mode
    /// computes `tag = E_K(0x10 ‖ nonce[..15], 0^128)`, and the published tag
    /// is `97d951f2fd129001483e831f2a6821e9`. It therefore pins the full
    /// Deoxys-BC-256 forward path (tweakey schedule + 14 rounds) against an
    /// official value, independently of the AEAD wrapper.
    #[test]
    fn deoxys_bc256_single_block_kat() {
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        // tweak = 0x10 (TWEAK_TAG prefix) ‖ nonce[0..15]
        let tweak: [u8; 16] = [
            0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
            0x2d, 0x2e,
        ];
        let plaintext = [0u8; 16];
        let expected: [u8; 16] = [
            0x97, 0xd9, 0x51, 0xf2, 0xfd, 0x12, 0x90, 0x01, 0x48, 0x3e, 0x83, 0x1f, 0x2a, 0x68,
            0x21, 0xe9,
        ];

        let bc = DeoxysBc256::new(&key);
        let ct = bc.encrypt_block(&tweak, &plaintext);
        assert_eq!(ct, expected, "Deoxys-BC-256 single-block KAT mismatch");
    }

    /// The tweakey schedule must be deterministic and tweak-sensitive: two
    /// different tweaks under the same key must (with overwhelming
    /// probability) produce different ciphertexts for the same plaintext.
    #[test]
    fn deoxys_bc256_tweak_sensitivity() {
        let key = [0x42u8; 16];
        let bc = DeoxysBc256::new(&key);
        let pt = [0x11u8; 16];
        let mut t1 = [0u8; 16];
        let mut t2 = [0u8; 16];
        t2[15] = 1;
        assert_ne!(
            bc.encrypt_block(&t1, &pt),
            bc.encrypt_block(&t2, &pt),
            "distinct tweaks must yield distinct ciphertexts"
        );
        // Determinism.
        t1[0] = 0xAA;
        assert_eq!(bc.encrypt_block(&t1, &pt), bc.encrypt_block(&t1, &pt));
    }
}
