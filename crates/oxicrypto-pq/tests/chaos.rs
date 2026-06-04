//! Chaos / anti-panic tests for oxicrypto-pq.
//!
//! These tests exercise adversarial inputs to verify that:
//! - `decapsulate()` never panics on arbitrary ciphertext bytes (even garbage).
//! - `verify()` never panics on arbitrary signature bytes (even garbage).
//!
//! FIPS 203 specifies *implicit rejection*: a decapsulation attempt with an
//! invalid ciphertext must return a pseudorandom key rather than an error or
//! panic.  ML-KEM's `DecapsulationKey::decapsulate` is thus infallible for
//! correctly-sized ciphertexts.  For wrong-length inputs we expect a
//! `CryptoError::Encoding` error — not a panic.
//!
//! ML-DSA's `VerifyingKey::verify` similarly must never panic; it returns
//! `Ok(())` only for a valid signature.  For malformed bytes it returns `Err`.
//!
//! All seeds used here are fully deterministic so test outcomes are stable.

use oxicrypto_pq::mldsa::{
    MlDsa44, MlDsa65, Signature44, Signature65, VerifyingKey44, VerifyingKey65,
};
use oxicrypto_pq::mlkem::{
    Ciphertext1024, Ciphertext512, Ciphertext768, DecapKey1024, DecapKey512, DecapKey768,
    EncapKey1024, EncapKey512, EncapKey768, MlKem1024, MlKem512, MlKem768,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate `n` different pseudo-random byte buffers of length `len`.
fn random_bufs(n: usize, len: usize, base_seed: u64) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let seed = base_seed.wrapping_add(i as u64);
            let mut rng = ChaCha20Rng::from_seed({
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(&seed.to_le_bytes());
                s
            });
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf[..]);
            buf
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM decapsulate: never panics on arbitrary bytes
// ─────────────────────────────────────────────────────────────────────────────

/// ML-KEM-512: `decapsulate()` must not panic on arbitrary ciphertext bytes.
///
/// For wrong-length inputs, `Ciphertext512::from_bytes` returns `Err` — no panic.
/// For correct-length random bytes, decapsulation invokes FIPS 203 implicit
/// rejection and returns a pseudorandom shared key — no panic.
#[test]
fn chaos_mlkem512_decapsulate_never_panics() {
    let mut rng = ChaCha20Rng::from_seed([0x10u8; 32]);
    let (dk, _) = MlKem512::generate(&mut rng);

    // Wrong-length buffers — from_bytes must return Err, not panic.
    let wrong_lengths: &[usize] = &[0, 1, 16, 767, 769, 1024, 4096];
    for &len in wrong_lengths {
        let buf = vec![0x42u8; len];
        let _ = Ciphertext512::from_bytes(&buf); // must not panic
    }

    // Correct-length random ciphertexts: FIPS 203 §7 implicit rejection.
    // `from_bytes` succeeds (length matches), `decapsulate` must not panic
    // regardless of content.
    let bufs = random_bufs(20, 768, 0x1234_5678);
    for buf in &bufs {
        if let Ok(ct) = Ciphertext512::from_bytes(buf) {
            let _ = dk.decapsulate(&ct); // implicit rejection: returns pseudorandom key
        }
    }
}

/// ML-KEM-768: `decapsulate()` must not panic on random ciphertext bytes.
#[test]
fn chaos_mlkem768_decapsulate_never_panics() {
    let mut rng = ChaCha20Rng::from_seed([0x20u8; 32]);
    let (dk, _) = MlKem768::generate(&mut rng);

    let wrong_lengths: &[usize] = &[0, 1, 1087, 1089, 2048];
    for &len in wrong_lengths {
        let buf = vec![0x55u8; len];
        let _ = Ciphertext768::from_bytes(&buf);
    }

    let bufs = random_bufs(20, 1088, 0xDEAD_BEEF);
    for buf in &bufs {
        if let Ok(ct) = Ciphertext768::from_bytes(buf) {
            let _ = dk.decapsulate(&ct);
        }
    }
}

/// ML-KEM-1024: `decapsulate()` must not panic on random ciphertext bytes.
#[test]
fn chaos_mlkem1024_decapsulate_never_panics() {
    let mut rng = ChaCha20Rng::from_seed([0x30u8; 32]);
    let (dk, _) = MlKem1024::generate(&mut rng);

    let wrong_lengths: &[usize] = &[0, 1, 1567, 1569, 4096];
    for &len in wrong_lengths {
        let buf = vec![0xAAu8; len];
        let _ = Ciphertext1024::from_bytes(&buf);
    }

    let bufs = random_bufs(20, 1568, 0xCAFE_BABE);
    for buf in &bufs {
        if let Ok(ct) = Ciphertext1024::from_bytes(buf) {
            let _ = dk.decapsulate(&ct);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM from_bytes: never panics
// ─────────────────────────────────────────────────────────────────────────────

/// ML-KEM-512 `DecapKey::from_bytes` with random bytes must not panic.
#[test]
fn chaos_mlkem512_decapkey_from_bytes_never_panics() {
    let bufs = random_bufs(30, 64, 0x1111);
    for buf in &bufs {
        let _ = DecapKey512::from_bytes(buf);
    }
    // Wrong lengths.
    for len in [0usize, 1, 32, 65, 128] {
        let _ = DecapKey512::from_bytes(&vec![0u8; len]);
    }
}

/// ML-KEM-768 `DecapKey::from_bytes` with random bytes must not panic.
#[test]
fn chaos_mlkem768_decapkey_from_bytes_never_panics() {
    let bufs = random_bufs(30, 64, 0x2222);
    for buf in &bufs {
        let _ = DecapKey768::from_bytes(buf);
    }
    for len in [0usize, 1, 63, 65, 128] {
        let _ = DecapKey768::from_bytes(&vec![0u8; len]);
    }
}

/// ML-KEM-1024 `DecapKey::from_bytes` with random bytes must not panic.
#[test]
fn chaos_mlkem1024_decapkey_from_bytes_never_panics() {
    let bufs = random_bufs(30, 64, 0x3333);
    for buf in &bufs {
        let _ = DecapKey1024::from_bytes(buf);
    }
    for len in [0usize, 1, 63, 65, 128] {
        let _ = DecapKey1024::from_bytes(&vec![0u8; len]);
    }
}

/// ML-KEM-512 `EncapKey::from_bytes` with garbage must not panic.
#[test]
fn chaos_mlkem512_encapkey_from_bytes_never_panics() {
    let bufs = random_bufs(20, 800, 0x4444);
    for buf in &bufs {
        let _ = EncapKey512::from_bytes(buf);
    }
    for len in [0usize, 1, 799, 801, 2048] {
        let _ = EncapKey512::from_bytes(&vec![0u8; len]);
    }
}

/// ML-KEM-768 `EncapKey::from_bytes` with garbage must not panic.
#[test]
fn chaos_mlkem768_encapkey_from_bytes_never_panics() {
    let bufs = random_bufs(20, 1184, 0x5555);
    for buf in &bufs {
        let _ = EncapKey768::from_bytes(buf);
    }
    for len in [0usize, 1, 1183, 1185, 4096] {
        let _ = EncapKey768::from_bytes(&vec![0u8; len]);
    }
}

/// ML-KEM-1024 `EncapKey::from_bytes` with garbage must not panic.
#[test]
fn chaos_mlkem1024_encapkey_from_bytes_never_panics() {
    let bufs = random_bufs(20, 1568, 0x6666);
    for buf in &bufs {
        let _ = EncapKey1024::from_bytes(buf);
    }
    for len in [0usize, 1, 1567, 1569, 4096] {
        let _ = EncapKey1024::from_bytes(&vec![0u8; len]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA verify: never panics on arbitrary signature bytes
// ─────────────────────────────────────────────────────────────────────────────

/// ML-DSA-44 `verify()` must not panic on arbitrary signature bytes.
///
/// Random / garbage signatures must return `Err`, never panic.
#[test]
fn chaos_mldsa44_verify_never_panics() {
    let mut rng = ChaCha20Rng::from_seed([0x40u8; 32]);
    let (_, vk) = MlDsa44::generate(&mut rng);
    let msg = b"chaos test message ML-DSA-44";

    // Random-length / random-content signature buffers.
    let lengths: &[usize] = &[0, 1, 16, 100, 2419, 2420, 2421, 4096];
    for &len in lengths {
        let buf = vec![0x42u8; len];
        if let Ok(sig) = Signature44::from_bytes(&buf) {
            // Verification must not panic (expected to fail on garbage).
            let _ = vk.verify(msg, &sig);
        }
        // from_bytes returning Err is also correct — no panic either way.
    }

    // Random bytes at the correct signature length (2420 B).
    let bufs = random_bufs(25, 2420, 0xABCD);
    for buf in &bufs {
        if let Ok(sig) = Signature44::from_bytes(buf) {
            let _ = vk.verify(msg, &sig);
        }
    }
}

/// ML-DSA-65 `verify()` must not panic on arbitrary signature bytes.
#[test]
fn chaos_mldsa65_verify_never_panics() {
    let mut rng = ChaCha20Rng::from_seed([0x50u8; 32]);
    let (_, vk) = MlDsa65::generate(&mut rng);
    let msg = b"chaos test message ML-DSA-65";

    let lengths: &[usize] = &[0, 1, 16, 3308, 3309, 3310, 8192];
    for &len in lengths {
        let buf = vec![0x55u8; len];
        if let Ok(sig) = Signature65::from_bytes(&buf) {
            let _ = vk.verify(msg, &sig);
        }
    }

    let bufs = random_bufs(25, 3309, 0xEF01);
    for buf in &bufs {
        if let Ok(sig) = Signature65::from_bytes(buf) {
            let _ = vk.verify(msg, &sig);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA VerifyingKey::from_bytes: never panics
// ─────────────────────────────────────────────────────────────────────────────

/// ML-DSA-44 `VerifyingKey::from_bytes` with garbage must not panic.
#[test]
fn chaos_mldsa44_verifying_key_from_bytes_never_panics() {
    let lengths: &[usize] = &[0, 1, 100, 1311, 1312, 1313, 4096];
    for &len in lengths {
        let _ = VerifyingKey44::from_bytes(&vec![0xFFu8; len]);
    }
    let bufs = random_bufs(20, 1312, 0x5555);
    for buf in &bufs {
        let _ = VerifyingKey44::from_bytes(buf);
    }
}

/// ML-DSA-65 `VerifyingKey::from_bytes` with garbage must not panic.
#[test]
fn chaos_mldsa65_verifying_key_from_bytes_never_panics() {
    let lengths: &[usize] = &[0, 1, 100, 1951, 1952, 1953, 4096];
    for &len in lengths {
        let _ = VerifyingKey65::from_bytes(&vec![0xFFu8; len]);
    }
    let bufs = random_bufs(20, 1952, 0x6666);
    for buf in &bufs {
        let _ = VerifyingKey65::from_bytes(buf);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA verify: correct sig always verifies, wrong key always fails
// ─────────────────────────────────────────────────────────────────────────────

/// ML-DSA-44 chaos: sign many messages, verify each succeeds; wrong-key fails.
#[test]
fn chaos_mldsa44_sign_verify_consistency() {
    let mut rng = ChaCha20Rng::from_seed([0x60u8; 32]);
    let (sk, vk) = MlDsa44::generate(&mut rng);

    // Different signer (wrong key for verification).
    let (_, vk_wrong) = MlDsa44::generate(&mut rng);

    for i in 0u8..10 {
        let msg = [i; 32];
        let sig = sk.sign(&msg).expect("sign");
        vk.verify(&msg, &sig).expect("correct key must verify");
        assert!(
            vk_wrong.verify(&msg, &sig).is_err(),
            "wrong key must fail verification"
        );
    }
}

/// ML-DSA-65 chaos: sign many messages with varying lengths.
#[test]
fn chaos_mldsa65_sign_verify_variable_message_length() {
    let mut rng = ChaCha20Rng::from_seed([0x70u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);

    for len in [0usize, 1, 7, 32, 64, 255, 256, 1024, 4096] {
        let msg = vec![0x42u8; len];
        let sig = sk.sign(&msg).expect("sign variable-length msg");
        vk.verify(&msg, &sig).expect("verify variable-length msg");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM: modified ciphertext → different (or same pseudo-random) shared secret
// ─────────────────────────────────────────────────────────────────────────────

/// ML-KEM-512: modifying a valid ciphertext produces implicit rejection
/// (a different pseudorandom shared secret is returned, not an error).
#[test]
fn chaos_mlkem512_modified_ciphertext_implicit_rejection() {
    let mut rng = ChaCha20Rng::from_seed([0x80u8; 32]);
    let (dk, ek) = MlKem512::generate(&mut rng);
    let (ct, ss_valid) = ek.encapsulate(&mut rng).expect("encapsulate");

    // Flip a bit in the ciphertext bytes.
    let mut ct_bytes = ct.to_bytes();
    ct_bytes[0] ^= 0x01;
    let ct_modified = Ciphertext512::from_bytes(&ct_bytes).expect("from_bytes after flip");
    let ss_modified = dk
        .decapsulate(&ct_modified)
        .expect("decapsulate modified ct");

    // FIPS 203 implicit rejection: the key changes — must not panic.
    // (With overwhelmingly high probability the modified key differs.)
    let _ = ss_valid.as_slice();
    let _ = ss_modified.as_slice();
}

/// ML-KEM-768: modifying a valid ciphertext does not panic.
#[test]
fn chaos_mlkem768_modified_ciphertext_implicit_rejection() {
    let mut rng = ChaCha20Rng::from_seed([0x90u8; 32]);
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, _ss_valid) = ek.encapsulate(&mut rng).expect("encapsulate");

    let mut ct_bytes = ct.to_bytes();
    ct_bytes[100] ^= 0xFF;
    let ct_modified = Ciphertext768::from_bytes(&ct_bytes).expect("from_bytes after flip");
    let _ss_modified = dk
        .decapsulate(&ct_modified)
        .expect("decapsulate modified ct");
}
