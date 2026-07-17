//! ML-DSA (FIPS 204) property-based tests.
//!
//! Invariants verified:
//! - sign → verify always succeeds on the original message.
//! - verify with a different message always fails.
//! - key serialization round-trips.
//! - context-string signing: different contexts yield different sigs, and
//!   verifying with the wrong context fails.

use oxicrypto_pq::mldsa::{MlDsa44, MlDsa65, MlDsa87};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const TEST_MSG: &[u8] = b"oxicrypto-pq ML-DSA property test message";
const ALT_MSG: &[u8] = b"oxicrypto-pq ML-DSA property test message - tampered";

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-44
// ─────────────────────────────────────────────────────────────────────────────

/// Property: sign → verify always succeeds.
#[test]
fn prop_mldsa44_sign_verify_round_trip() {
    for i in 0u8..3 {
        let mut rng = ChaCha20Rng::from_seed([i; 32]);
        let (sk, vk) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign");
        vk.verify(TEST_MSG, &sig)
            .expect("verify must succeed for the original message");
    }
}

/// Property: verify with wrong message always fails.
#[test]
fn prop_mldsa44_wrong_message_fails() {
    let mut rng = ChaCha20Rng::from_seed([0xA4u8; 32]);
    let (sk, vk) = MlDsa44::generate(&mut rng);
    let sig = sk.sign(TEST_MSG).expect("sign");
    assert!(
        vk.verify(ALT_MSG, &sig).is_err(),
        "ML-DSA-44: wrong message must fail verification"
    );
}

/// Property: key serialization round-trips.
#[test]
fn test_mldsa44_key_serialization() {
    use oxicrypto_pq::mldsa::{Signature44, SigningKey44, VerifyingKey44};

    let mut rng = ChaCha20Rng::from_seed([0xB4u8; 32]);
    let (sk, vk) = MlDsa44::generate(&mut rng);

    let sk_bytes = sk.to_bytes();
    let vk_bytes = vk.to_bytes();

    assert_eq!(vk_bytes.len(), MlDsa44::VERIFYING_KEY_LEN);
    // Signing key is serialized as a 32-byte seed.
    assert_eq!(sk_bytes.len(), 32);

    let sk2 = SigningKey44::from_bytes(&sk_bytes).expect("SigningKey44::from_bytes");
    let vk2 = VerifyingKey44::from_bytes(&vk_bytes).expect("VerifyingKey44::from_bytes");

    let sig = sk2.sign(TEST_MSG).expect("sign with deserialized key");
    let sig_bytes = sig.to_bytes();
    assert_eq!(sig_bytes.len(), MlDsa44::SIGNATURE_LEN);

    let sig2 = Signature44::from_bytes(&sig_bytes).expect("Signature44::from_bytes");
    vk2.verify(TEST_MSG, &sig2)
        .expect("verify with deserialized key and signature");
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-65
// ─────────────────────────────────────────────────────────────────────────────

/// Property: sign → verify always succeeds.
#[test]
fn prop_mldsa65_sign_verify_round_trip() {
    for i in 0u8..5 {
        let mut rng = ChaCha20Rng::from_seed([i; 32]);
        let (sk, vk) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign");
        vk.verify(TEST_MSG, &sig)
            .expect("verify must succeed for the original message");
    }
}

/// Property: verify with wrong message always fails.
#[test]
fn prop_mldsa65_wrong_message_fails() {
    let mut rng = ChaCha20Rng::from_seed([0xA5u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);
    let sig = sk.sign(TEST_MSG).expect("sign");
    assert!(
        vk.verify(ALT_MSG, &sig).is_err(),
        "ML-DSA-65: wrong message must fail verification"
    );
}

/// Property: key serialization round-trips.
#[test]
fn test_mldsa65_key_serialization() {
    use oxicrypto_pq::mldsa::{Signature65, SigningKey65, VerifyingKey65};

    let mut rng = ChaCha20Rng::from_seed([0xB5u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);

    let sk_bytes = sk.to_bytes();
    let vk_bytes = vk.to_bytes();

    assert_eq!(vk_bytes.len(), MlDsa65::VERIFYING_KEY_LEN);
    assert_eq!(sk_bytes.len(), 32, "signing key seed must be 32 bytes");

    let sk2 = SigningKey65::from_bytes(&sk_bytes).expect("SigningKey65::from_bytes");
    let vk2 = VerifyingKey65::from_bytes(&vk_bytes).expect("VerifyingKey65::from_bytes");

    let sig = sk2.sign(TEST_MSG).expect("sign with deserialized key");
    let sig_bytes = sig.to_bytes();
    assert_eq!(sig_bytes.len(), MlDsa65::SIGNATURE_LEN);

    let sig2 = Signature65::from_bytes(&sig_bytes).expect("Signature65::from_bytes");
    vk2.verify(TEST_MSG, &sig2)
        .expect("verify with deserialized key and signature");
}

/// Property: context-string domain separation — different contexts produce
/// signatures that fail verification under the wrong context.
#[test]
fn test_mldsa65_context_string_domain_separation() {
    use oxicrypto_pq::mldsa::{mldsa65_sign_ctx, mldsa65_verify_ctx};

    let mut rng = ChaCha20Rng::from_seed([0xC5u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);

    let sk_bytes = sk.to_bytes();
    let vk_bytes = vk.to_bytes();

    let ctx_a: &[u8] = b"application-A";
    let ctx_b: &[u8] = b"application-B";

    let mut sig_a = vec![0u8; MlDsa65::SIGNATURE_LEN];
    let sig_a_len = mldsa65_sign_ctx(&sk_bytes, TEST_MSG, ctx_a, &mut sig_a, &mut rng)
        .expect("sign with ctx_a");

    let mut sig_b = vec![0u8; MlDsa65::SIGNATURE_LEN];
    let sig_b_len = mldsa65_sign_ctx(&sk_bytes, TEST_MSG, ctx_b, &mut sig_b, &mut rng)
        .expect("sign with ctx_b");

    // Correct context verifies.
    mldsa65_verify_ctx(&vk_bytes, TEST_MSG, ctx_a, &sig_a[..sig_a_len])
        .expect("verify with correct ctx_a must succeed");
    mldsa65_verify_ctx(&vk_bytes, TEST_MSG, ctx_b, &sig_b[..sig_b_len])
        .expect("verify with correct ctx_b must succeed");

    // Wrong context fails.
    assert!(
        mldsa65_verify_ctx(&vk_bytes, TEST_MSG, ctx_b, &sig_a[..sig_a_len]).is_err(),
        "verifying sig_a with ctx_b must fail"
    );
    assert!(
        mldsa65_verify_ctx(&vk_bytes, TEST_MSG, ctx_a, &sig_b[..sig_b_len]).is_err(),
        "verifying sig_b with ctx_a must fail"
    );

    // Empty context is distinct from non-empty context.
    let mut sig_empty = vec![0u8; MlDsa65::SIGNATURE_LEN];
    let sig_empty_len = mldsa65_sign_ctx(&sk_bytes, TEST_MSG, b"", &mut sig_empty, &mut rng)
        .expect("sign with empty context");
    assert!(
        mldsa65_verify_ctx(&vk_bytes, TEST_MSG, ctx_a, &sig_empty[..sig_empty_len]).is_err(),
        "empty-context sig must fail verification under non-empty context"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-87  (spawned in a dedicated 2 MiB thread to avoid stack overflow)
// ─────────────────────────────────────────────────────────────────────────────

/// Shared stack size for ML-DSA-87 tests. 2 MiB comfortably covers the measured
/// worst-case (debug) footprint of ~768 KiB — see `oxicrypto_pq::stack_safe`.
const MLDSA87_STACK: usize = oxicrypto_pq::OXICRYPTO_MLDSA_STACK;

/// Property: sign → verify always succeeds for ML-DSA-87.
#[test]
fn prop_mldsa87_sign_verify_round_trip() {
    std::thread::Builder::new()
        .stack_size(MLDSA87_STACK)
        .spawn(|| {
            for i in 0u8..3 {
                let mut rng = ChaCha20Rng::from_seed([i; 32]);
                let (sk, vk) = MlDsa87::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign");
                vk.verify(TEST_MSG, &sig)
                    .expect("verify must succeed for the original message");
            }
        })
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

/// Property: ML-DSA-87 verify with wrong message always fails.
#[test]
fn prop_mldsa87_wrong_message_fails() {
    std::thread::Builder::new()
        .stack_size(MLDSA87_STACK)
        .spawn(|| {
            let mut rng = ChaCha20Rng::from_seed([0xA7u8; 32]);
            let (sk, vk) = MlDsa87::generate(&mut rng);
            let sig = sk.sign(TEST_MSG).expect("sign");
            assert!(
                vk.verify(ALT_MSG, &sig).is_err(),
                "ML-DSA-87: wrong message must fail verification"
            );
        })
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}
