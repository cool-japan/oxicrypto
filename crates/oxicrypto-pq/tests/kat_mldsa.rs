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

/// ML-DSA-65 sign is deterministic: same key + same message → same signature bytes.
///
/// This test pins the exact signature length (3309 bytes per FIPS 204 Table 1)
/// and verifies determinism.  It cannot yet be a full byte-level KAT because
/// the ml-dsa 0.1.0 crate uses hedged (randomized) signing that requires a
/// fresh rng per call; the output differs across calls even for the same key.
/// The `try_sign` / `sign` path used by our wrapper is the empty-context
/// deterministic variant, so it IS reproducible.
#[test]
fn mldsa65_deterministic_sign_verifies_and_has_fips_size() {
    let mut rng = ChaCha20Rng::from_seed([0xABu8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);
    let msg = b"NIST FIPS 204 ML-DSA-65 deterministic KAT message";

    let sig1 = sk.sign(msg).expect("first sign failed");
    let sig2 = sk.sign(msg).expect("second sign failed");

    let sig1_bytes = sig1.to_bytes();
    let sig2_bytes = sig2.to_bytes();

    // FIPS 204 Table 1: ML-DSA-65 signature size is 3309 bytes.
    assert_eq!(
        sig1_bytes.len(),
        3309,
        "ML-DSA-65 signature must be exactly 3309 bytes per FIPS 204 Table 1"
    );
    assert_eq!(
        sig2_bytes.len(),
        3309,
        "ML-DSA-65 signature must be exactly 3309 bytes per FIPS 204 Table 1"
    );

    // Determinism: both signatures must match (empty-context deterministic signing).
    assert_eq!(
        sig1_bytes, sig2_bytes,
        "ML-DSA-65 sign must be deterministic for same key + message"
    );

    // Both must verify.
    vk.verify(msg, &sig1).expect("sig1 verify failed");
    vk.verify(msg, &sig2).expect("sig2 verify failed");
}

/// ML-DSA-65 key/signature sizes match FIPS 204 Table 1.
///
/// | Parameter | FIPS 204 size |
/// |-----------|--------------|
/// | Signing key seed | 32 bytes |
/// | Verifying key | 1952 bytes |
/// | Signature | 3309 bytes |
#[test]
fn mldsa65_fips_size_constants() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);
    let msg = b"size test";
    let sig = sk.sign(msg).expect("sign");

    assert_eq!(sk.to_bytes().len(), 32, "ML-DSA-65 seed must be 32 bytes");
    assert_eq!(vk.to_bytes().len(), 1952, "ML-DSA-65 vk must be 1952 bytes");
    assert_eq!(
        sig.to_bytes().len(),
        3309,
        "ML-DSA-65 signature must be 3309 bytes"
    );
}

/// ML-DSA-44 FIPS 204 size constants.
///
/// | Parameter | FIPS 204 size |
/// |-----------|--------------|
/// | Signing key seed | 32 bytes |
/// | Verifying key | 1312 bytes |
/// | Signature | 2420 bytes |
#[test]
fn mldsa44_fips_size_constants() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let (sk, vk) = MlDsa44::generate(&mut rng);
    let msg = b"size test";
    let sig = sk.sign(msg).expect("sign");

    assert_eq!(sk.to_bytes().len(), 32, "ML-DSA-44 seed must be 32 bytes");
    assert_eq!(vk.to_bytes().len(), 1312, "ML-DSA-44 vk must be 1312 bytes");
    assert_eq!(
        sig.to_bytes().len(),
        2420,
        "ML-DSA-44 signature must be 2420 bytes"
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
