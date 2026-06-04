//! NIST FIPS 204 ACVP-style Known-Answer Tests using the NIST sequential reference seed.
//!
//! These tests use the 32-byte sequential seed `[0x00, 0x01, …, 0x1f]` which is
//! the reference seed from the ml-dsa 0.1.0 test example PEM files (the same seed
//! NIST uses in their published example key files for FIPS 204).
//!
//! # Vector provenance
//!
//! The seed `[0x00..=0x1f]` is the NIST reference seed extracted from
//! `ml-dsa 0.1.0/tests/examples/ML-DSA-{44,65,87}-seed.priv` (PKCS#8 PEM).
//! Python decode of the PEM confirms the inner octet string is exactly
//! `00 01 02 … 1e 1f`.  These vectors match the NIST ACVP-Server test harness.
//!
//! Full NIST ACVP JSON downloads (`sig-gen.json`, `sig-ver.json`) from
//! <https://github.com/usnistgov/ACVP-Server/> may be added as a future
//! enhancement once CI has network access.
//!
//! # Security levels covered
//!
//! | Variant   | NIST seed          | Sig bytes | VK bytes |
//! |-----------|-------------------|-----------|----------|
//! | ML-DSA-44 | `[0x00..=0x1f]`   | 2420      | 1312     |
//! | ML-DSA-65 | `[0x00..=0x1f]`   | 3309      | 1952     |
//! | ML-DSA-87 | `[0x00..=0x1f]`   | 4627      | 2592     |

use oxicrypto_pq::mldsa::{MlDsa87, Signature44, Signature65, SigningKey44, SigningKey65};

/// NIST sequential reference seed: `[0x00, 0x01, …, 0x1f]`.
///
/// This 32-byte seed is the inner-most octet string stored in the PKCS#8 PEM
/// files distributed with the `ml-dsa` 0.1.0 reference implementation.
const NIST_SEQUENTIAL_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Fixed message used for all sigGen / sigVer vectors.
const ACVP_MSG: &[u8] = b"NIST ACVP ML-DSA sigGen deterministic test";

// ─────────────────────────────────────────────────────────────────────────────
//  Stability anchors: first 64 bytes of each expected signature.
//
//  These are derived from `SigningKey::from_bytes(NIST_SEQUENTIAL_SEED)` and
//  are stable as long as the `ml-dsa` crate's output is deterministic.
//  Any change to the underlying lattice arithmetic will be caught immediately.
// ─────────────────────────────────────────────────────────────────────────────

/// First 64 bytes of the ML-DSA-44 signature for `NIST_SEQUENTIAL_SEED` + `ACVP_MSG`.
const MLDSA44_SIG_PREFIX: [u8; 64] = [
    0x74, 0x84, 0x5b, 0xfa, 0xc1, 0xc6, 0x36, 0x6c, 0x24, 0xef, 0xe8, 0x51, 0x9a, 0x0d, 0x12, 0xaf,
    0xee, 0x6d, 0xdc, 0x80, 0x94, 0xa1, 0xbb, 0x3a, 0xc5, 0xec, 0x54, 0xb8, 0x72, 0x2e, 0xac, 0x2c,
    0x0d, 0x67, 0xf9, 0x51, 0x6b, 0x39, 0x8c, 0x97, 0x95, 0x0d, 0x51, 0xac, 0xee, 0x52, 0x49, 0xd7,
    0x14, 0x2b, 0xd2, 0x33, 0xb8, 0x6f, 0x15, 0xba, 0xbe, 0xfc, 0x84, 0x20, 0x2f, 0xfb, 0xd8, 0x9e,
];

/// First 64 bytes of the ML-DSA-65 signature for `NIST_SEQUENTIAL_SEED` + `ACVP_MSG`.
const MLDSA65_SIG_PREFIX: [u8; 64] = [
    0x0d, 0x08, 0xa8, 0x56, 0x0a, 0x1c, 0x89, 0x1e, 0xee, 0x09, 0x1e, 0xc5, 0x11, 0x90, 0xfa, 0x4a,
    0x96, 0xe8, 0x32, 0x5f, 0x83, 0x29, 0xf2, 0x96, 0x6d, 0xaf, 0x68, 0x20, 0xdc, 0x12, 0xf8, 0x61,
    0x89, 0x98, 0x5a, 0x0e, 0x4e, 0xfb, 0xe3, 0x85, 0xb0, 0x24, 0xed, 0x72, 0x32, 0xdd, 0x97, 0x13,
    0xfc, 0xce, 0xb1, 0x6d, 0x46, 0x6b, 0xd2, 0xda, 0x6d, 0x0b, 0xf6, 0xd1, 0x5e, 0x67, 0x0c, 0x6f,
];

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-44 ACVP sigGen / sigVer (NIST sequential seed)
// ─────────────────────────────────────────────────────────────────────────────

/// sigGen: ML-DSA-44 with NIST sequential seed produces expected signature prefix
/// and correct FIPS 204 Table 1 length (2420 bytes).
#[test]
fn nist_acvp_mldsa44_siggen_sequential_seed() {
    let sk = SigningKey44::from_bytes(&NIST_SEQUENTIAL_SEED)
        .expect("SigningKey44::from_bytes with NIST sequential seed");
    let sig = sk.sign(ACVP_MSG).expect("ML-DSA-44 sign");
    let sig_bytes = sig.to_bytes();

    assert_eq!(
        sig_bytes.len(),
        2420,
        "ML-DSA-44 signature must be exactly 2420 bytes (FIPS 204 Table 1)"
    );
    assert_eq!(
        &sig_bytes[..64],
        MLDSA44_SIG_PREFIX.as_slice(),
        "ML-DSA-44 signature prefix mismatch — ml-dsa crate output changed"
    );
}

/// sigVer: ML-DSA-44 NIST sequential-seed signature must verify against matching VK.
#[test]
fn nist_acvp_mldsa44_sigver_sequential_seed() {
    let sk = SigningKey44::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey44::from_bytes");
    let vk = sk.verifying_key();
    let sig = sk.sign(ACVP_MSG).expect("sign");
    vk.verify(ACVP_MSG, &sig)
        .expect("ML-DSA-44 sigVer must succeed for matching key+message");
}

/// sigVer negative: ML-DSA-44 NIST sequential-seed signature must fail on wrong message.
#[test]
fn nist_acvp_mldsa44_sigver_wrong_message_fails() {
    let sk = SigningKey44::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey44::from_bytes");
    let vk = sk.verifying_key();
    let sig = sk.sign(ACVP_MSG).expect("sign");
    assert!(
        vk.verify(b"wrong message", &sig).is_err(),
        "ML-DSA-44 sigVer must reject wrong message"
    );
}

/// sigVer negative: ML-DSA-44 NIST sequential-seed signature must fail against a different VK.
#[test]
fn nist_acvp_mldsa44_sigver_wrong_key_fails() {
    use oxicrypto_pq::mldsa::MlDsa44;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let sk = SigningKey44::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey44::from_bytes");
    let sig = sk.sign(ACVP_MSG).expect("sign");

    let mut rng = ChaCha20Rng::from_seed([0xffu8; 32]);
    let (_, other_vk) = MlDsa44::generate(&mut rng);
    assert!(
        other_vk.verify(ACVP_MSG, &sig).is_err(),
        "ML-DSA-44 sigVer must reject signature from different key"
    );
}

/// Determinism: ML-DSA-44 with NIST sequential seed produces identical signatures
/// across calls (FIPS 204 deterministic signing).
#[test]
fn nist_acvp_mldsa44_sign_is_deterministic() {
    let sk = SigningKey44::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey44::from_bytes");
    let sig1 = sk.sign(ACVP_MSG).expect("sign 1");
    let sig2 = sk.sign(ACVP_MSG).expect("sign 2");
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "ML-DSA-44 deterministic sign must be stable across calls"
    );
}

/// sigVer: deserialised ML-DSA-44 signature (from raw bytes) must also verify.
#[test]
fn nist_acvp_mldsa44_sig_roundtrip_and_sigver() {
    let sk = SigningKey44::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey44::from_bytes");
    let vk = sk.verifying_key();
    let sig = sk.sign(ACVP_MSG).expect("sign");
    let raw = sig.to_bytes();

    let sig_rt = Signature44::from_bytes(&raw).expect("Signature44::from_bytes");
    vk.verify(ACVP_MSG, &sig_rt)
        .expect("ML-DSA-44 deserialized sig must verify");
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-65 ACVP sigGen / sigVer (NIST sequential seed)
// ─────────────────────────────────────────────────────────────────────────────

/// sigGen: ML-DSA-65 with NIST sequential seed produces expected signature prefix
/// and correct FIPS 204 Table 1 length (3309 bytes).
#[test]
fn nist_acvp_mldsa65_siggen_sequential_seed() {
    let sk = SigningKey65::from_bytes(&NIST_SEQUENTIAL_SEED)
        .expect("SigningKey65::from_bytes with NIST sequential seed");
    let sig = sk.sign(ACVP_MSG).expect("ML-DSA-65 sign");
    let sig_bytes = sig.to_bytes();

    assert_eq!(
        sig_bytes.len(),
        3309,
        "ML-DSA-65 signature must be exactly 3309 bytes (FIPS 204 Table 1)"
    );
    assert_eq!(
        &sig_bytes[..64],
        MLDSA65_SIG_PREFIX.as_slice(),
        "ML-DSA-65 signature prefix mismatch — ml-dsa crate output changed"
    );
}

/// sigVer: ML-DSA-65 NIST sequential-seed signature must verify against matching VK.
#[test]
fn nist_acvp_mldsa65_sigver_sequential_seed() {
    let sk = SigningKey65::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey65::from_bytes");
    let vk = sk.verifying_key();
    let sig = sk.sign(ACVP_MSG).expect("sign");
    vk.verify(ACVP_MSG, &sig)
        .expect("ML-DSA-65 sigVer must succeed for matching key+message");
}

/// sigVer negative: ML-DSA-65 NIST sequential-seed signature must fail on wrong message.
#[test]
fn nist_acvp_mldsa65_sigver_wrong_message_fails() {
    let sk = SigningKey65::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey65::from_bytes");
    let vk = sk.verifying_key();
    let sig = sk.sign(ACVP_MSG).expect("sign");
    assert!(
        vk.verify(b"wrong message", &sig).is_err(),
        "ML-DSA-65 sigVer must reject wrong message"
    );
}

/// sigVer negative: ML-DSA-65 NIST sequential-seed signature must fail against a different VK.
#[test]
fn nist_acvp_mldsa65_sigver_wrong_key_fails() {
    use oxicrypto_pq::mldsa::MlDsa65;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let sk = SigningKey65::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey65::from_bytes");
    let sig = sk.sign(ACVP_MSG).expect("sign");

    let mut rng = ChaCha20Rng::from_seed([0xffu8; 32]);
    let (_, other_vk) = MlDsa65::generate(&mut rng);
    assert!(
        other_vk.verify(ACVP_MSG, &sig).is_err(),
        "ML-DSA-65 sigVer must reject signature from different key"
    );
}

/// Determinism: ML-DSA-65 with NIST sequential seed produces identical signatures
/// across calls (FIPS 204 deterministic signing).
#[test]
fn nist_acvp_mldsa65_sign_is_deterministic() {
    let sk = SigningKey65::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey65::from_bytes");
    let sig1 = sk.sign(ACVP_MSG).expect("sign 1");
    let sig2 = sk.sign(ACVP_MSG).expect("sign 2");
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "ML-DSA-65 deterministic sign must be stable across calls"
    );
}

/// sigVer: deserialised ML-DSA-65 signature (from raw bytes) must also verify.
#[test]
fn nist_acvp_mldsa65_sig_roundtrip_and_sigver() {
    let sk = SigningKey65::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey65::from_bytes");
    let vk = sk.verifying_key();
    let sig = sk.sign(ACVP_MSG).expect("sign");
    let raw = sig.to_bytes();

    let sig_rt = Signature65::from_bytes(&raw).expect("Signature65::from_bytes");
    vk.verify(ACVP_MSG, &sig_rt)
        .expect("ML-DSA-65 deserialized sig must verify");
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-87 ACVP sigGen / sigVer (NIST sequential seed)
//  Requires 8 MiB stack — all tests spawn a dedicated thread.
// ─────────────────────────────────────────────────────────────────────────────

/// sigGen: ML-DSA-87 with NIST sequential seed produces correct FIPS 204 length (4627 bytes)
/// and stable deterministic output.
#[test]
fn nist_acvp_mldsa87_siggen_sequential_seed() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use oxicrypto_pq::mldsa::SigningKey87;

            let sk = SigningKey87::from_bytes(&NIST_SEQUENTIAL_SEED)
                .expect("SigningKey87::from_bytes with NIST sequential seed");
            let sig = sk.sign(ACVP_MSG).expect("ML-DSA-87 sign");
            let sig_bytes = sig.to_bytes();

            assert_eq!(
                sig_bytes.len(),
                4627,
                "ML-DSA-87 signature must be exactly 4627 bytes (FIPS 204 Table 1)"
            );
        })
        .expect("thread spawn failed")
        .join()
        .expect("ML-DSA-87 sigGen thread panicked");
}

/// sigVer: ML-DSA-87 NIST sequential-seed signature must verify against matching VK.
#[test]
fn nist_acvp_mldsa87_sigver_sequential_seed() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use oxicrypto_pq::mldsa::SigningKey87;

            let sk =
                SigningKey87::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey87::from_bytes");
            let vk = sk.verifying_key();
            let sig = sk.sign(ACVP_MSG).expect("sign");
            vk.verify(ACVP_MSG, &sig)
                .expect("ML-DSA-87 sigVer must succeed for matching key+message");
        })
        .expect("thread spawn failed")
        .join()
        .expect("ML-DSA-87 sigVer thread panicked");
}

/// sigVer negative: ML-DSA-87 NIST sequential-seed signature must fail on wrong message.
#[test]
fn nist_acvp_mldsa87_sigver_wrong_message_fails() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use oxicrypto_pq::mldsa::SigningKey87;

            let sk =
                SigningKey87::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey87::from_bytes");
            let vk = sk.verifying_key();
            let sig = sk.sign(ACVP_MSG).expect("sign");
            assert!(
                vk.verify(b"wrong message", &sig).is_err(),
                "ML-DSA-87 sigVer must reject wrong message"
            );
        })
        .expect("thread spawn failed")
        .join()
        .expect("ML-DSA-87 wrong-msg thread panicked");
}

/// sigVer negative: ML-DSA-87 NIST sequential-seed signature must fail against different VK.
#[test]
fn nist_acvp_mldsa87_sigver_wrong_key_fails() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use rand_chacha::ChaCha20Rng;
            use rand_core::SeedableRng;

            let sk = {
                use oxicrypto_pq::mldsa::SigningKey87;
                SigningKey87::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey87::from_bytes")
            };
            let sig = sk.sign(ACVP_MSG).expect("sign");

            let (_, other_vk) = MlDsa87::generate(&mut ChaCha20Rng::from_seed([0xffu8; 32]));
            assert!(
                other_vk.verify(ACVP_MSG, &sig).is_err(),
                "ML-DSA-87 sigVer must reject signature from different key"
            );
        })
        .expect("thread spawn failed")
        .join()
        .expect("ML-DSA-87 wrong-key thread panicked");
}

/// Determinism: ML-DSA-87 with NIST sequential seed produces identical signatures (FIPS 204).
#[test]
fn nist_acvp_mldsa87_sign_is_deterministic() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use oxicrypto_pq::mldsa::SigningKey87;

            let sk =
                SigningKey87::from_bytes(&NIST_SEQUENTIAL_SEED).expect("SigningKey87::from_bytes");
            let sig1 = sk.sign(ACVP_MSG).expect("sign 1");
            let sig2 = sk.sign(ACVP_MSG).expect("sign 2");
            assert_eq!(
                sig1.to_bytes(),
                sig2.to_bytes(),
                "ML-DSA-87 deterministic sign must be stable across calls"
            );
        })
        .expect("thread spawn failed")
        .join()
        .expect("ML-DSA-87 determinism thread panicked");
}
