//! Fuzz-style tests: `open()` on random bytes must never panic.
//!
//! Runs 1000 random ciphertexts through `open()` for each AEAD algorithm and
//! asserts only `Err` is returned — no panic, no undefined behaviour.

use oxicrypto_aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, SyntheticIvAes256Gcm};
use oxicrypto_core::Aead;

/// Simple deterministic pseudo-RNG (LCG) for test reproducibility.
struct TestRng {
    state: u64,
}

impl TestRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u8(&mut self) -> u8 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 33) as u8
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_u8();
        }
    }

    fn next_range(&mut self, lo: usize, hi: usize) -> usize {
        if lo >= hi {
            return lo;
        }
        let range = hi - lo;
        let v = self.next_u8() as usize;
        lo + (v % range)
    }
}

fn fuzz_open<A: Aead>(aead: &A, key: &[u8], nonce: &[u8]) {
    let mut rng = TestRng::new(0x1234_5678_9ABC_DEF0);

    // Minimum byte count that `open` could reasonably accept: tag_len + a few bytes.
    let min_len = aead.tag_len();
    let max_len = min_len + 128;

    for _ in 0..1000 {
        let len = rng.next_range(0, max_len + 1);
        let mut random_ct = vec![0u8; len];
        rng.fill(&mut random_ct);

        let pt_len = len.saturating_sub(aead.tag_len());
        let mut pt_out = vec![0u8; pt_len];

        // Must not panic — only return Ok or Err.
        let _ = aead.open(key, nonce, b"aad", &random_ct, &mut pt_out);
    }
}

#[test]
fn fuzz_open_nopanic_aes128gcm() {
    fuzz_open(&Aes128Gcm, &[0x42u8; 16], &[0x11u8; 12]);
}

#[test]
fn fuzz_open_nopanic_aes256gcm() {
    fuzz_open(&Aes256Gcm, &[0x42u8; 32], &[0x11u8; 12]);
}

#[test]
fn fuzz_open_nopanic_chacha20poly1305() {
    fuzz_open(&ChaCha20Poly1305, &[0x42u8; 32], &[0x11u8; 12]);
}

#[test]
fn fuzz_open_nopanic_synthetic_iv_gcm() {
    // SyntheticIvAes256Gcm uses nonce = &[].
    let aead = SyntheticIvAes256Gcm;
    let key = [0x42u8; 32];
    let mut rng = TestRng::new(0xCAFE_BABE_DEAD_BEEF);

    let min_len = aead.tag_len();
    let max_len = min_len + 128;

    for _ in 0..1000 {
        let len = rng.next_range(0, max_len + 1);
        let mut random_ct = vec![0u8; len];
        rng.fill(&mut random_ct);

        let pt_len = len.saturating_sub(aead.tag_len());
        let mut pt_out = vec![0u8; pt_len];

        // Must not panic.
        let _ = aead.open(&key, &[], b"aad", &random_ct, &mut pt_out);
    }
}
