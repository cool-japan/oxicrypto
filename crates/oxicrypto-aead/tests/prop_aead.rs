//! Property-based tests for AEAD implementations.
//!
//! These tests verify that `seal` followed by `open` always recovers the
//! original plaintext for 50 randomly-generated inputs per algorithm.

use oxicrypto_aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
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
        // LCG parameters from Knuth.
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

    fn next_len(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        let v = self.next_u8() as usize;
        v % (max + 1)
    }
}

fn prop_seal_open_impl<A: Aead>(aead: &A, key: &[u8], nonce: &[u8]) {
    let mut rng = TestRng::new(0xDEAD_BEEF_CAFE_BABE);

    for _ in 0..50 {
        let pt_len = rng.next_len(256);
        let aad_len = rng.next_len(64);

        let mut pt = vec![0u8; pt_len];
        let mut aad = vec![0u8; aad_len];
        rng.fill(&mut pt);
        rng.fill(&mut aad);

        // Seal.
        let ct = aead
            .seal_to_vec(key, nonce, &aad, &pt)
            .expect("seal failed");

        // Open.
        let recovered = aead
            .open_to_vec(key, nonce, &aad, &ct)
            .expect("open failed");

        assert_eq!(recovered, pt, "seal→open must recover original plaintext");
    }
}

#[test]
fn prop_seal_open_aes128gcm() {
    prop_seal_open_impl(&Aes128Gcm, &[0x42u8; 16], &[0x11u8; 12]);
}

#[test]
fn prop_seal_open_aes256gcm() {
    prop_seal_open_impl(&Aes256Gcm, &[0x42u8; 32], &[0x11u8; 12]);
}

#[test]
fn prop_seal_open_chacha20poly1305() {
    prop_seal_open_impl(&ChaCha20Poly1305, &[0x42u8; 32], &[0x11u8; 12]);
}
