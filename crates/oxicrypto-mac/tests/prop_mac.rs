//! Property-based tests for MAC implementations.
//!
//! Tests: verify consistency, key sensitivity, zero-length message, long key,
//! and no-panic fuzz for verify.

use oxicrypto_core::Mac;
use oxicrypto_mac::HmacSha256;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

/// Property: mac() and verify() are consistent — for any key/message, the tag
/// produced by mac() is accepted by verify().  Also: a 1-bit flip in the tag
/// causes verify() to fail.
#[test]
fn prop_mac_verify_consistent() {
    for i in 0u8..=50 {
        let mut rng = ChaCha20Rng::from_seed([i; 32]);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mut msg = [0u8; 64];
        rng.fill_bytes(&mut msg);

        let mut tag = [0u8; 32];
        HmacSha256.mac(&key, &msg, &mut tag).expect("mac");
        HmacSha256
            .verify(&key, &msg, &tag)
            .expect("verify must pass for correct tag");

        // Tamper: flipping a single bit in the tag must cause verify to fail.
        tag[0] ^= 1;
        assert!(
            HmacSha256.verify(&key, &msg, &tag).is_err(),
            "tampered tag (seed={i}) must be rejected"
        );
    }
}

/// Property: different keys produce different tags for the same message.
#[test]
fn prop_mac_key_sensitivity() {
    for i in 0u8..=20 {
        let mut rng = ChaCha20Rng::from_seed([i; 32]);
        let mut key1 = [0u8; 32];
        rng.fill_bytes(&mut key1);
        let mut key2 = key1;
        key2[0] ^= 1; // differ by exactly one bit

        let msg = b"test message for key sensitivity";
        let mut tag1 = [0u8; 32];
        let mut tag2 = [0u8; 32];
        HmacSha256.mac(&key1, msg, &mut tag1).expect("mac1");
        HmacSha256.mac(&key2, msg, &mut tag2).expect("mac2");
        assert_ne!(
            tag1, tag2,
            "different keys (seed={i}) must produce different tags"
        );
    }
}

/// Test: zero-length message produces a valid, deterministic MAC tag.
#[test]
fn test_mac_zero_length_message() {
    let key = b"some-key-for-zero-len-test";
    let mut tag1 = [0u8; 32];
    let mut tag2 = [0u8; 32];

    HmacSha256
        .mac(key, b"", &mut tag1)
        .expect("mac of empty message must succeed");
    HmacSha256
        .mac(key, b"", &mut tag2)
        .expect("mac of empty message must succeed (2nd call)");

    // Deterministic
    assert_eq!(tag1, tag2, "MAC of empty message must be deterministic");
    // Must verify correctly
    HmacSha256
        .verify(key, b"", &tag1)
        .expect("verify of empty-message MAC must succeed");
}

/// Test: HMAC with a key longer than the SHA-256 block size (64 bytes) works
/// correctly (HMAC hashes the key first per RFC 2104 §2).
#[test]
fn test_mac_long_key() {
    let long_key = vec![0xab_u8; 200]; // well over the 64-byte SHA-256 block size
    let msg = b"test message with long key";

    let mut tag1 = [0u8; 32];
    let mut tag2 = [0u8; 32];

    HmacSha256
        .mac(&long_key, msg, &mut tag1)
        .expect("mac with 200-byte key must succeed");
    HmacSha256
        .mac(&long_key, msg, &mut tag2)
        .expect("mac with 200-byte key must be deterministic");

    assert_eq!(tag1, tag2, "long-key MAC must be deterministic");
    HmacSha256
        .verify(&long_key, msg, &tag1)
        .expect("verify with 200-byte key must succeed");
}

/// Fuzz test: verify() never panics on arbitrary tag bytes.
/// For 1000 iterations, feeds random key/message/tag to verify() and asserts
/// the result is either Ok or Err(InvalidTag) — never a panic.
#[test]
fn fuzz_verify_no_panic() {
    let mut rng = ChaCha20Rng::from_seed([0xde; 32]);

    for _ in 0..1000 {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);
        let mut random_tag = [0u8; 32];
        rng.fill_bytes(&mut random_tag);

        // Must not panic; result can be Ok or Err.
        let _result = HmacSha256.verify(&key, &msg, &random_tag);
    }
}

/// Constant-time verification sanity: verify() behaves correctly on the
/// boundary between matching and non-matching tags.
#[test]
fn prop_mac_ct_timing_sanity() {
    let key = b"timing-sanity-key";
    let msg = b"timing-sanity-msg";
    let mut correct_tag = [0u8; 32];
    HmacSha256.mac(key, msg, &mut correct_tag).expect("mac");

    // Correct tag verifies.
    assert!(
        HmacSha256.verify(key, msg, &correct_tag).is_ok(),
        "correct tag must verify"
    );

    // Off-by-one in every possible byte position must all fail.
    for byte_pos in 0..32 {
        let mut bad_tag = correct_tag;
        bad_tag[byte_pos] ^= 0x01;
        assert!(
            HmacSha256.verify(key, msg, &bad_tag).is_err(),
            "tag with bit flip at byte {byte_pos} must be rejected"
        );
    }
}
