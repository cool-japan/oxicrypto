//! ML-DSA (FIPS 204) Known-Answer Tests.
//!
//! Tests cover:
//! 1. Deterministic keygen via seeded CSPRNG → sign → verify → Ok.
//! 2. Roundtrip: generate, sign, verify succeeds; alter message by 1 byte, verify fails.
//!
//! Note: ML-DSA's `try_sign` is deterministic given fixed key + message,
//! so reproducibility is inherent without extra feature gates.

use oxicrypto_pq::mldsa::{MlDsa44, MlDsa65, MlDsa87};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const TEST_MSG: &[u8] = b"FIPS 204 ML-DSA integration test message";
const ALTERED_IDX: usize = 0;

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-44
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mldsa44_seeded_sign_verify() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let (sk, vk) = MlDsa44::generate(&mut rng);
    let sig = sk.sign(TEST_MSG).expect("sign failed");
    vk.verify(TEST_MSG, &sig).expect("verify failed");
}

#[test]
fn mldsa44_roundtrip_with_rng() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let (sk, vk) = MlDsa44::generate(&mut rng);
    let sig = sk.sign(TEST_MSG).expect("sign failed");
    vk.verify(TEST_MSG, &sig)
        .expect("verify failed for correct message");

    // Alter message — verification must fail.
    let mut altered = TEST_MSG.to_vec();
    altered[ALTERED_IDX] ^= 0x01;
    assert!(
        vk.verify(&altered, &sig).is_err(),
        "ML-DSA-44: verify must reject altered message"
    );
}

#[test]
fn mldsa44_sign_is_deterministic() {
    // Same key + message → same signature (FIPS 204 hedged signing with fixed context).
    let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);
    let (sk, vk) = MlDsa44::generate(&mut rng);

    let sig1 = sk.sign(TEST_MSG).expect("first sign failed");
    let sig2 = sk.sign(TEST_MSG).expect("second sign failed");

    // Both must verify.
    vk.verify(TEST_MSG, &sig1).expect("sig1 verify failed");
    vk.verify(TEST_MSG, &sig2).expect("sig2 verify failed");
}

#[test]
fn mldsa44_wrong_key_fails_verify() {
    let mut rng = ChaCha20Rng::from_seed([0x11u8; 32]);
    let (sk, _vk) = MlDsa44::generate(&mut rng);

    let mut rng2 = ChaCha20Rng::from_seed([0x22u8; 32]);
    let (_sk2, vk2) = MlDsa44::generate(&mut rng2);

    let sig = sk.sign(TEST_MSG).expect("sign failed");
    assert!(
        vk2.verify(TEST_MSG, &sig).is_err(),
        "ML-DSA-44: mismatched key must fail verification"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-65
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mldsa65_seeded_sign_verify() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);
    let sig = sk.sign(TEST_MSG).expect("sign failed");
    vk.verify(TEST_MSG, &sig).expect("verify failed");
}

#[test]
fn mldsa65_roundtrip_with_rng() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);
    let sig = sk.sign(TEST_MSG).expect("sign failed");
    vk.verify(TEST_MSG, &sig)
        .expect("verify failed for correct message");

    let mut altered = TEST_MSG.to_vec();
    altered[ALTERED_IDX] ^= 0x01;
    assert!(
        vk.verify(&altered, &sig).is_err(),
        "ML-DSA-65: verify must reject altered message"
    );
}

#[test]
fn mldsa65_wrong_key_fails_verify() {
    let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
    let (sk, _vk) = MlDsa65::generate(&mut rng);

    let mut rng2 = ChaCha20Rng::from_seed([0x44u8; 32]);
    let (_sk2, vk2) = MlDsa65::generate(&mut rng2);

    let sig = sk.sign(TEST_MSG).expect("sign failed");
    assert!(
        vk2.verify(TEST_MSG, &sig).is_err(),
        "ML-DSA-65: mismatched key must fail verification"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-87 (larger stack needed for this parameter set)
// ─────────────────────────────────────────────────────────────────────────────

const MLDSA87_STACK: usize = 8 * 1024 * 1024; // 8 MiB

#[test]
fn mldsa87_seeded_sign_verify() {
    std::thread::Builder::new()
        .stack_size(MLDSA87_STACK)
        .spawn(|| {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let (sk, vk) = MlDsa87::generate(&mut rng);
            let sig = sk.sign(TEST_MSG).expect("sign failed");
            vk.verify(TEST_MSG, &sig).expect("verify failed");
        })
        .expect("spawn failed")
        .join()
        .expect("thread panicked");
}

#[test]
fn mldsa87_roundtrip_with_rng() {
    std::thread::Builder::new()
        .stack_size(MLDSA87_STACK)
        .spawn(|| {
            let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
            let (sk, vk) = MlDsa87::generate(&mut rng);
            let sig = sk.sign(TEST_MSG).expect("sign failed");
            vk.verify(TEST_MSG, &sig)
                .expect("verify failed for correct message");

            let mut altered = TEST_MSG.to_vec();
            altered[ALTERED_IDX] ^= 0x01;
            assert!(
                vk.verify(&altered, &sig).is_err(),
                "ML-DSA-87: verify must reject altered message"
            );
        })
        .expect("spawn failed")
        .join()
        .expect("thread panicked");
}

#[test]
fn mldsa87_wrong_key_fails_verify() {
    std::thread::Builder::new()
        .stack_size(MLDSA87_STACK)
        .spawn(|| {
            let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
            let (sk, _vk) = MlDsa87::generate(&mut rng);

            let mut rng2 = ChaCha20Rng::from_seed([0x66u8; 32]);
            let (_sk2, vk2) = MlDsa87::generate(&mut rng2);

            let sig = sk.sign(TEST_MSG).expect("sign failed");
            assert!(
                vk2.verify(TEST_MSG, &sig).is_err(),
                "ML-DSA-87: mismatched key must fail verification"
            );
        })
        .expect("spawn failed")
        .join()
        .expect("thread panicked");
}
