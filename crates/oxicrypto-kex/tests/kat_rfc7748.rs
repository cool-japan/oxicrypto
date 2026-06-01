//! RFC 7748 Known-Answer Tests (KAT) for X25519 and X448.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc7748>
//!
//! Section 6.1 — X25519 Alice-and-Bob vectors
//! Section 6.2 — X448  Alice-and-Bob vectors
//! Section 5.2 — X25519 and X448 iterated tests

use oxicrypto_core::{CryptoError, KeyAgreement};
use oxicrypto_kex::{X25519, X448};

// ── helpers ───────────────────────────────────────────────────────────────────

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn hex_to_56(s: &str) -> [u8; 56] {
    let bytes = hex::decode(s).expect("valid hex");
    let mut arr = [0u8; 56];
    arr.copy_from_slice(&bytes);
    arr
}

// ── RFC 7748 §6.1 — X25519 test vectors ──────────────────────────────────────

/// RFC 7748 §6.1: Alice's side of the X25519 DH exchange.
/// Alice computes `X25519(alice_priv, bob_pub)` and must match the shared secret.
#[test]
fn rfc7748_x25519_alice_side() {
    let alice_priv = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_pub = hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let expected = hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let kex = X25519;
    let mut shared = [0u8; 32];
    kex.agree(&alice_priv, &bob_pub, &mut shared)
        .expect("X25519 Alice agree failed");
    assert_eq!(
        shared, expected,
        "RFC 7748 §6.1 X25519 Alice shared secret mismatch"
    );
}

/// RFC 7748 §6.1: Bob's side of the X25519 DH exchange.
/// Bob computes `X25519(bob_priv, alice_pub)` and must match the shared secret.
#[test]
fn rfc7748_x25519_bob_side() {
    let bob_priv = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let alice_pub = hex_to_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let expected = hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let kex = X25519;
    let mut shared = [0u8; 32];
    kex.agree(&bob_priv, &alice_pub, &mut shared)
        .expect("X25519 Bob agree failed");
    assert_eq!(
        shared, expected,
        "RFC 7748 §6.1 X25519 Bob shared secret mismatch"
    );
}

/// RFC 7748 §6.1: Alice's public key from her private key.
/// Alice's public key = X25519(alice_priv, basepoint); basepoint u = 9.
#[test]
fn rfc7748_x25519_alice_public_key() {
    let alice_priv = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let expected_pub =
        hex_to_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

    let kex = X25519;
    // X25519 base-point u-coordinate = 9 (LE 32 bytes)
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let mut pub_key = [0u8; 32];
    kex.agree(&alice_priv, &basepoint, &mut pub_key)
        .expect("X25519 Alice public key derivation failed");
    assert_eq!(
        pub_key, expected_pub,
        "RFC 7748 §6.1 X25519 Alice public key mismatch"
    );
}

/// RFC 7748 §6.1: Bob's public key from his private key.
#[test]
fn rfc7748_x25519_bob_public_key() {
    let bob_priv = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let expected_pub =
        hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    let kex = X25519;
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let mut pub_key = [0u8; 32];
    kex.agree(&bob_priv, &basepoint, &mut pub_key)
        .expect("X25519 Bob public key derivation failed");
    assert_eq!(
        pub_key, expected_pub,
        "RFC 7748 §6.1 X25519 Bob public key mismatch"
    );
}

/// RFC 7748 §6.1: X25519 agree_to_vec convenience method.
#[test]
fn rfc7748_x25519_agree_to_vec() {
    let alice_priv = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_pub = hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let expected = hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let kex = X25519;
    let shared = kex
        .agree_to_vec(&alice_priv, &bob_pub)
        .expect("X25519 agree_to_vec failed");
    assert_eq!(shared.len(), 32);
    assert_eq!(
        shared.as_slice(),
        expected.as_slice(),
        "agree_to_vec mismatch"
    );
}

// ── RFC 7748 §5.2 — X25519 iterated test ─────────────────────────────────────
//
// Algorithm (from RFC 7748 §5.2):
//   k = u = 9 (as 32-byte LE)
//   For each iteration: result = X25519(k, u); u = k; k = result
//
// After 1 iteration:
//   422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
//
// After 1,000 iterations:
//   684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51

/// RFC 7748 §5.2: X25519 iterated 1 time.
#[test]
fn rfc7748_x25519_iter_1() {
    let kex = X25519;
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = [0u8; 32];
    u[0] = 9;

    let expected = hex_to_32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

    let mut result = [0u8; 32];
    kex.agree(&k, &u, &mut result)
        .expect("X25519 iteration 1 failed");
    assert_eq!(result, expected, "RFC 7748 §5.2 X25519 after 1 iteration");
}

/// RFC 7748 §5.2: X25519 iterated 1,000 times.
#[test]
fn rfc7748_x25519_iter_1000() {
    let kex = X25519;
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = [0u8; 32];
    u[0] = 9;

    let expected = hex_to_32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

    let mut result = [0u8; 32];
    for _ in 0..1000 {
        kex.agree(&k, &u, &mut result)
            .expect("X25519 iteration failed");
        u = k;
        k = result;
    }
    assert_eq!(
        result, expected,
        "RFC 7748 §5.2 X25519 after 1,000 iterations"
    );
}

// ── RFC 7748 §6.2 — X448 test vectors ────────────────────────────────────────
//
// Hex values verified against the x448 crate's own RFC 7748 test vectors
// (ed448-goldilocks 0.7.2 implementation, crate version x448 0.6.0).

/// RFC 7748 §6.2: Alice's side of the X448 DH exchange.
#[test]
fn rfc7748_x448_alice_side() {
    // Alice's private key (56 bytes)
    let alice_priv = hex_to_56("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    // Bob's public key
    let bob_pub = hex_to_56("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    // Expected shared secret
    let expected = hex_to_56("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    let kex = X448;
    let mut shared = [0u8; 56];
    kex.agree(&alice_priv, &bob_pub, &mut shared)
        .expect("X448 Alice agree failed");
    assert_eq!(
        shared, expected,
        "RFC 7748 §6.2 X448 Alice shared secret mismatch"
    );
}

/// RFC 7748 §6.2: Bob's side of the X448 DH exchange.
#[test]
fn rfc7748_x448_bob_side() {
    let bob_priv = hex_to_56("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    let alice_pub = hex_to_56("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
    let expected = hex_to_56("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    let kex = X448;
    let mut shared = [0u8; 56];
    kex.agree(&bob_priv, &alice_pub, &mut shared)
        .expect("X448 Bob agree failed");
    assert_eq!(
        shared, expected,
        "RFC 7748 §6.2 X448 Bob shared secret mismatch"
    );
}

/// RFC 7748 §6.2: Alice's X448 public key from her private key.
/// Public key = X448(alice_priv, base_point), base_point u = 5 (LE 56 bytes).
#[test]
fn rfc7748_x448_alice_public_key() {
    let alice_priv = hex_to_56("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let expected_pub = hex_to_56("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");

    let kex = X448;
    // X448 base point: u = 5 as a 56-byte little-endian value
    let mut basepoint = [0u8; 56];
    basepoint[0] = 5;
    let mut pub_key = [0u8; 56];
    kex.agree(&alice_priv, &basepoint, &mut pub_key)
        .expect("X448 Alice public key derivation failed");
    assert_eq!(
        pub_key, expected_pub,
        "RFC 7748 §6.2 X448 Alice public key mismatch"
    );
}

/// RFC 7748 §6.2: Bob's X448 public key from his private key.
#[test]
fn rfc7748_x448_bob_public_key() {
    let bob_priv = hex_to_56("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    let expected_pub = hex_to_56("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");

    let kex = X448;
    let mut basepoint = [0u8; 56];
    basepoint[0] = 5;
    let mut pub_key = [0u8; 56];
    kex.agree(&bob_priv, &basepoint, &mut pub_key)
        .expect("X448 Bob public key derivation failed");
    assert_eq!(
        pub_key, expected_pub,
        "RFC 7748 §6.2 X448 Bob public key mismatch"
    );
}

/// RFC 7748 §6.2: X448 agree_to_vec convenience method.
#[test]
fn rfc7748_x448_agree_to_vec() {
    let alice_priv = hex_to_56("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let bob_pub = hex_to_56("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    let expected = hex_to_56("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    let kex = X448;
    let shared = kex
        .agree_to_vec(&alice_priv, &bob_pub)
        .expect("X448 agree_to_vec failed");
    assert_eq!(shared.len(), 56);
    assert_eq!(
        shared.as_slice(),
        expected.as_slice(),
        "X448 agree_to_vec mismatch"
    );
}

// ── RFC 7748 §5.2 — X448 iterated test ───────────────────────────────────────
//
// Algorithm (from RFC 7748 §5.2):
//   k = u = X448 base-point (u = 5, 56-byte LE)
//   For each iteration: result = X448(k, u); u = k; k = result
//
// After 1 iteration:
//   3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113
//
// After 1,000 iterations:
//   aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38

/// RFC 7748 §5.2: X448 iterated 1 time.
#[test]
fn rfc7748_x448_iter_1() {
    let kex = X448;
    // X448 base point: u = 5
    let mut k = [0u8; 56];
    k[0] = 5;
    let mut u = [0u8; 56];
    u[0] = 5;

    let expected = hex_to_56("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");

    let mut result = [0u8; 56];
    kex.agree(&k, &u, &mut result)
        .expect("X448 iteration 1 failed");
    assert_eq!(result, expected, "RFC 7748 §5.2 X448 after 1 iteration");
}

/// RFC 7748 §5.2: X448 iterated 1,000 times.
#[test]
fn rfc7748_x448_iter_1000() {
    let kex = X448;
    let mut k = [0u8; 56];
    k[0] = 5;
    let mut u = [0u8; 56];
    u[0] = 5;

    let expected = hex_to_56("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38");

    let mut result = [0u8; 56];
    for _ in 0..1000 {
        kex.agree(&k, &u, &mut result)
            .expect("X448 iteration failed");
        u = k;
        k = result;
    }
    assert_eq!(
        result, expected,
        "RFC 7748 §5.2 X448 after 1,000 iterations"
    );
}

// ── API surface tests ─────────────────────────────────────────────────────────

/// Verify that X448 has the correct trait metadata.
#[test]
fn x448_trait_metadata() {
    let kex = X448;
    assert_eq!(kex.name(), "X448");
    assert_eq!(kex.scalar_len(), 56);
    assert_eq!(kex.point_len(), 56);
    assert_eq!(kex.shared_secret_len(), 56);
}

/// Verify that X25519 shared_secret_len returns 32.
#[test]
fn x25519_shared_secret_len() {
    let kex = X25519;
    assert_eq!(kex.shared_secret_len(), 32);
}

/// Verify X448 rejects a secret that is too short.
#[test]
fn x448_reject_short_secret() {
    let kex = X448;
    let mut shared = [0u8; 56];
    let result = kex.agree(&[0u8; 32], &[5u8; 56], &mut shared);
    assert_eq!(result, Err(CryptoError::InvalidKey));
}

/// Verify X448 rejects a public key that is too short.
#[test]
fn x448_reject_short_public() {
    let kex = X448;
    let mut shared = [0u8; 56];
    let result = kex.agree(&[0u8; 56], &[5u8; 32], &mut shared);
    // short public key → try_into() fails → InvalidKey error (length mismatch)
    assert_eq!(result, Err(CryptoError::InvalidKey));
}

/// Verify X448 rejects output buffer that is too small.
#[test]
fn x448_reject_small_buffer() {
    let alice_priv = hex_to_56("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let bob_pub = hex_to_56("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");

    let kex = X448;
    let mut shared = [0u8; 32]; // too small (need 56)
    let result = kex.agree(&alice_priv, &bob_pub, &mut shared);
    assert_eq!(result, Err(CryptoError::BufferTooSmall));
}

/// Verify X448 rejects the all-zero low-order public key.
#[test]
fn x448_reject_low_order_zero_public_key() {
    let alice_priv = hex_to_56("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let zero_pub = [0u8; 56]; // all-zero is a low-order point on Curve448

    let kex = X448;
    let mut shared = [0u8; 56];
    let result = kex.agree(&alice_priv, &zero_pub, &mut shared);
    assert_eq!(
        result,
        Err(CryptoError::Kex),
        "X448 must reject all-zero (low-order) public key"
    );
}

/// Verify X448 DH commutativity: agree(a_priv, b_pub) == agree(b_priv, a_pub).
#[test]
fn x448_dh_commutativity() {
    let alice_priv = hex_to_56("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let bob_priv = hex_to_56("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");

    let kex = X448;
    let mut basepoint = [0u8; 56];
    basepoint[0] = 5;

    let mut alice_pub = [0u8; 56];
    kex.agree(&alice_priv, &basepoint, &mut alice_pub)
        .expect("Alice pub key");
    let mut bob_pub = [0u8; 56];
    kex.agree(&bob_priv, &basepoint, &mut bob_pub)
        .expect("Bob pub key");

    let mut alice_shared = [0u8; 56];
    kex.agree(&alice_priv, &bob_pub, &mut alice_shared)
        .expect("Alice agree");
    let mut bob_shared = [0u8; 56];
    kex.agree(&bob_priv, &alice_pub, &mut bob_shared)
        .expect("Bob agree");

    assert_eq!(alice_shared, bob_shared, "X448 DH must be commutative");
    assert_ne!(alice_shared, [0u8; 56]);
}
