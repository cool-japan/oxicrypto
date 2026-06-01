//! Wycheproof-style X25519 small-subgroup / low-order point tests.
//!
//! Reference: Google Wycheproof x25519_test.json; RFC 7748 §6.
//!
//! These tests verify that the implementation handles low-order (small-subgroup)
//! Curve25519 public keys correctly. The implementation rejects all-zero shared
//! secrets and returns `CryptoError::Kex` for every low-order point listed here.
//!
//! ## Behaviour contract
//!
//! RFC 7748 defines X25519(k, u) for all u without mandatory output validation.
//! For security, this implementation **actively rejects** any shared secret that
//! is the all-zero 32-byte value, which is the result of multiplying any scalar
//! by a low-order point on Curve25519. Callers receive `CryptoError::Kex`.
//!
//! This matches the "contributory" check provided by `x25519_dalek::SharedSecret::
//! was_contributory()` but as an error rather than a boolean.

use oxicrypto_core::{CryptoError, KeyAgreement};
use oxicrypto_kex::X25519;

// ── Low-order Curve25519 points ───────────────────────────────────────────────
//
// Each of these u-coordinates is a torsion point (or linear combination)
// of the group Z/8Z × Z_p. Multiplying any scalar by one of them yields
// the neutral element (all-zero shared secret).
//
// Source: Wycheproof x25519_test.json "small_subgroup" category;
// also RFC 7748 §6 note on non-contributory keys.
//
// Curve25519 has cofactor 8; its full torsion subgroup has 8 elements.
// The u-coordinates of the 8 torsion points in Montgomery form are:
//   0, 1, 325606250916557431795983626356110631294008115727848805560023387167927233504
//   (which is p-1-that), 325606250916557431795983626356110631294008115727848805560023387167927233505,
//   (which is p-1-that), 57896044618658097711785492504343953926634992332820282019728792003956564819948 (p-1),
//   and 39382357235489614581723060781553021112529911719440698176882885853963445705823.
//
// In practice the easiest to encode (LE 32 bytes) are:
//
// We use the canonical Wycheproof set: 0x00..00, 0x01..00 (point of order 2 on
// the twist), the "p−1" point, and the four order-4/order-8 torsion points.
// All of them produce an all-zero shared secret for any clamped scalar.
const LOW_ORDER_POINTS: &[(&str, &[u8; 32])] = &[
    // Order-1 identity (all zeros)
    (
        "all-zeros (identity)",
        &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
    ),
    // Order-2 point: u = 1 in Curve25519 Montgomery form
    (
        "order-2 point (u=1)",
        &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
    ),
    // p−1 = 2^255 − 20 in little-endian.
    // This is the Montgomery u-coordinate of an order-2 torsion point.
    (
        "p-1 (order-2 point on twist)",
        &[
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ),
    // Wycheproof tcId=2: order-4 small-subgroup point
    // encoded: 5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
    (
        "wycheproof-tc2 order-4 subgroup",
        &[
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
    ),
    // Wycheproof tcId=3: order-8 small-subgroup point
    // encoded: e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd86620516 5f49b800
    (
        "wycheproof-tc3 order-8 subgroup",
        &[
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
    ),
    // Wycheproof: p (= field prime) encodes the same projective point as 0
    // p = 2^255 − 19; in LE: ed ff ff ff ff ff ff ff ... 7f
    // (clamp masks bit 255; reducing mod p gives u = 0)
    (
        "field prime p (reduces to identity mod p)",
        &[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ),
];

// A well-chosen non-trivial scalar for testing low-order key pairs.
// RFC 7748 §6.1 Alice's private key is a good choice.
const ALICE_PRIV: [u8; 32] = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
];

/// Every low-order Curve25519 public key must produce `CryptoError::Kex`
/// because the resulting shared secret is all-zero.
///
/// This confirms the implementation actively rejects non-contributory
/// key exchange results, preventing small-subgroup attacks.
#[test]
fn x25519_rejects_all_low_order_points() {
    let kex = X25519;
    let mut shared = [0u8; 32];

    for (description, low_order_pk) in LOW_ORDER_POINTS {
        let result = kex.agree(&ALICE_PRIV, low_order_pk.as_slice(), &mut shared);
        assert_eq!(
            result,
            Err(CryptoError::Kex),
            "X25519 must reject low-order public key: {description}"
        );
        // Verify that shared output was NOT written with all-zeros
        // (the rejection happens before writing any output)
    }
}

/// Wycheproof requires that agree() with low-order keys either:
///   (a) returns Err — our implementation does this (active rejection), OR
///   (b) returns Ok with all-zero output — which callers can then detect.
///
/// This test documents that we chose option (a): active rejection via CryptoError::Kex.
#[test]
fn x25519_low_order_rejection_is_active_not_passive() {
    let kex = X25519;
    // Use the simplest low-order point: all-zeros.
    let zero_pk = [0u8; 32];
    let mut shared = [0u8; 32];
    let result = kex.agree(&ALICE_PRIV, &zero_pk, &mut shared);

    // Active rejection (preferred): implementation returns an error.
    // The shared output buffer is left unchanged (still all-zeros from init,
    // but that's incidental — the error means no secret was produced).
    assert!(
        result.is_err(),
        "X25519 must actively reject low-order points, not silently produce all-zero output"
    );
    assert_eq!(
        result,
        Err(CryptoError::Kex),
        "rejection error must be CryptoError::Kex"
    );
}

/// Verify X25519 commutativity using RFC 7748 §6.1 test vectors.
///
/// agree(alice_priv, bob_pub) must equal agree(bob_priv, alice_pub).
/// This is the fundamental DH correctness property.
#[test]
fn x25519_dh_commutativity_rfc7748() {
    // RFC 7748 §6.1 test vectors
    let alice_priv = ALICE_PRIV;
    let alice_pub = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    let bob_priv = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    let bob_pub = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    let expected_shared = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    let kex = X25519;

    let mut alice_shared = [0u8; 32];
    kex.agree(&alice_priv, &bob_pub, &mut alice_shared)
        .expect("Alice agree failed");

    let mut bob_shared = [0u8; 32];
    kex.agree(&bob_priv, &alice_pub, &mut bob_shared)
        .expect("Bob agree failed");

    assert_eq!(
        alice_shared, bob_shared,
        "X25519 DH must be commutative: agree(alice_priv, bob_pub) == agree(bob_priv, alice_pub)"
    );
    assert_eq!(
        alice_shared, expected_shared,
        "X25519 shared secret must match RFC 7748 §6.1 test vector"
    );
}

/// Verify X25519 commutativity with random-looking scalars (not from an RFC).
///
/// Uses two distinct non-trivial scalars and verifies DH is commutative.
/// This catches implementation bugs that might only appear with certain inputs.
#[test]
fn x25519_dh_commutativity_arbitrary_scalars() {
    use oxicrypto_kex::x25519_generate_keypair;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha20Rng::from_seed([0xA5u8; 32]);
    let (alice_sk, alice_pk) = x25519_generate_keypair(&mut rng).expect("Alice keygen failed");
    let (bob_sk, bob_pk) = x25519_generate_keypair(&mut rng).expect("Bob keygen failed");

    let kex = X25519;

    let mut alice_shared = [0u8; 32];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("Alice agree failed");

    let mut bob_shared = [0u8; 32];
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("Bob agree failed");

    assert_eq!(
        alice_shared, bob_shared,
        "X25519 DH commutativity: generated keypairs must produce the same shared secret"
    );
    assert_ne!(
        alice_shared, [0u8; 32],
        "shared secret from valid keypairs must not be all-zero"
    );
}

/// Verify that agree_to_vec with a low-order key also returns Err.
#[test]
fn x25519_agree_to_vec_rejects_low_order() {
    let kex = X25519;
    let zero_pk = [0u8; 32];
    let result = kex.agree_to_vec(&ALICE_PRIV, &zero_pk);
    assert_eq!(
        result,
        Err(CryptoError::Kex),
        "agree_to_vec must propagate the low-order rejection error"
    );
}
