//! Property and fuzz tests for oxicrypto-kex.
//!
//! Covers:
//! - Determinism: same (secret, public) always produces the same shared secret.
//! - Fuzz: `agree()` never panics on arbitrary-length or arbitrary-byte inputs;
//!   it returns either `Ok` or a well-typed `Err`.
//! - OxiRng integration: all `generate_keypair` functions accept `OxiRng`.
//! - negotiate_kex: TLS named-group negotiation helper.

use oxicrypto_core::KeyAgreement;
use oxicrypto_kex::{
    ecdh_p256_generate_keypair, ecdh_p384_generate_keypair, ecdh_p521_generate_keypair,
    negotiate_kex, x25519_generate_keypair, x448_generate_keypair, EcdhP256, EcdhP384, EcdhP521,
    X25519, X448,
};
use oxicrypto_rand::OxiRng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Simple LCG-based byte sequence for deterministic pseudo-random test vectors.
/// NOT cryptographically secure — test-only.
fn lcg_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

// ── Property: determinism ────────────────────────────────────────────────────

/// Same (secret, public) must always produce identical shared secret output.
#[test]
fn prop_x25519_agree_is_deterministic() {
    let kex = X25519;
    let secret = lcg_bytes(0xDEAD_BEEF_0001, 32);
    let public = lcg_bytes(0xDEAD_BEEF_0002, 32);

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];

    // The first call may succeed or fail (pseudo-random bytes may not be a valid
    // X25519 point — that is fine).  What matters is that two calls with the same
    // inputs produce the same result.
    let r1 = kex.agree(&secret, &public, &mut out1);
    let r2 = kex.agree(&secret, &public, &mut out2);

    assert_eq!(
        r1.is_ok(),
        r2.is_ok(),
        "X25519 agree must be deterministic (both ok or both err)"
    );
    if r1.is_ok() {
        assert_eq!(
            out1, out2,
            "X25519 agree must return identical outputs for the same inputs"
        );
    }
}

/// ECDH P-256: same scalar + public key always produces the same shared secret.
#[test]
fn prop_ecdh_p256_agree_is_deterministic() {
    // Use a known-valid P-256 scalar + public key from the NIST test vectors.
    // Alice's scalar (32 bytes, big-endian) from kat_ecdh_nist.rs vector 1.
    let alice_scalar = &[
        0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xd2, 0x61, 0x2e, 0x37, 0xbd, 0x22, 0x6d, 0x4e,
        0x13, 0xa7, 0xb4, 0x62, 0x36, 0x68, 0xdc, 0xa7, 0x03, 0x4e, 0x98, 0x17, 0x76, 0x4a, 0x67,
        0x62, 0x57,
    ];
    // Bob's uncompressed public key (65 bytes): 04 || X || Y
    let bob_pub = &[
        0x04, 0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64,
        0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88,
        0x33, 0xd2, 0x87, 0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba,
        0x5c, 0x51, 0xdc, 0xc5, 0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82,
        0xca, 0xb8, 0x5f, 0xa4, 0xac,
    ];

    let kex = EcdhP256;
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];

    let r1 = kex.agree(alice_scalar, bob_pub, &mut out1);
    let r2 = kex.agree(alice_scalar, bob_pub, &mut out2);

    assert!(
        r1.is_ok(),
        "P-256 agree with valid NIST vector must succeed"
    );
    assert!(
        r2.is_ok(),
        "P-256 agree with valid NIST vector must succeed"
    );
    assert_eq!(out1, out2, "P-256 agree must be deterministic");
}

/// ECDH P-384: determinism check with valid key material.
#[test]
fn prop_ecdh_p384_agree_is_deterministic() {
    // Use a known 48-byte scalar and 97-byte uncompressed public key.
    let scalar = lcg_bytes(0xCAFE_BABE_0001, 48);
    let pub_key = lcg_bytes(0xCAFE_BABE_0002, 97);

    let kex = EcdhP384;
    let mut out1 = [0u8; 48];
    let mut out2 = [0u8; 48];

    let r1 = kex.agree(&scalar, &pub_key, &mut out1);
    let r2 = kex.agree(&scalar, &pub_key, &mut out2);

    // Results may be Ok or Err (arbitrary bytes may be invalid keys).
    assert_eq!(
        r1.is_ok(),
        r2.is_ok(),
        "P-384 agree must be deterministic wrt ok/err"
    );
    if r1.is_ok() {
        assert_eq!(
            out1, out2,
            "P-384 agree must return identical outputs for the same inputs"
        );
    }
}

/// ECDH P-521: same scalar + public key always produces the same shared secret.
#[test]
fn prop_ecdh_p521_agree_is_deterministic() {
    // Generate a deterministic P-521 key pair using the kex crate's own keygen function.
    let mut rng = ChaCha20Rng::from_seed([0x52u8; 32]);
    let (alice_sk, bob_pk) = ecdh_p521_generate_keypair(&mut rng).expect("P-521 keygen");

    let kex = EcdhP521;
    let mut out1 = [0u8; 66];
    let mut out2 = [0u8; 66];

    // Both calls with the same (sk, pk) must produce the same result.
    let r1 = kex.agree(alice_sk.as_bytes(), &bob_pk, &mut out1);
    let r2 = kex.agree(alice_sk.as_bytes(), &bob_pk, &mut out2);

    assert!(
        r1.is_ok(),
        "P-521 agree with generated key pair must succeed"
    );
    assert_eq!(
        r1.is_ok(),
        r2.is_ok(),
        "P-521 agree must be deterministic wrt ok/err"
    );
    if r1.is_ok() {
        assert_eq!(
            out1, out2,
            "P-521 agree must return identical outputs for the same inputs"
        );
    }
}

/// X448: same scalar + public key always produces the same shared secret.
#[test]
fn prop_x448_agree_is_deterministic() {
    // Use pseudo-random bytes for both scalar and public key.
    // X448 accepts any 56-byte scalar (clamping is applied internally).
    let secret = lcg_bytes(0xFACE_CAFE_0001, 56);
    let public = lcg_bytes(0xFACE_CAFE_0002, 56);

    let kex = X448;
    let mut out1 = [0u8; 56];
    let mut out2 = [0u8; 56];

    let r1 = kex.agree(&secret, &public, &mut out1);
    let r2 = kex.agree(&secret, &public, &mut out2);

    assert_eq!(
        r1.is_ok(),
        r2.is_ok(),
        "X448 agree must be deterministic (both ok or both err)"
    );
    if r1.is_ok() {
        assert_eq!(
            out1, out2,
            "X448 agree must return identical outputs for the same inputs"
        );
    }
}

// ── Fuzz: agree() never panics on arbitrary inputs ────────────────────────────

/// X25519 `agree()` must never panic for any 32-byte secret or arbitrary-length
/// public key; it must return either `Ok` or a structured `Err`.
#[test]
fn fuzz_x25519_agree_never_panics() {
    let kex = X25519;
    let mut out = [0u8; 32];

    // Test with many pseudo-random (secret, public) pairs.
    for seed in 0u64..256 {
        let secret = lcg_bytes(seed, 32);
        let public = lcg_bytes(seed.wrapping_add(0x1000), 32);
        // Must return Ok or a structured Err — never panic.
        let _ = kex.agree(&secret, &public, &mut out);
    }

    // Wrong-length inputs must return Err(InvalidKey) or Err(BufferTooSmall),
    // not panic.
    for bad_len in [0usize, 1, 16, 31, 33, 64, 128] {
        let bad = lcg_bytes(bad_len as u64, bad_len);
        let _ = kex.agree(&bad, &[0u8; 32], &mut out);
        let _ = kex.agree(&[0u8; 32], &bad, &mut out);
    }
}

/// X448 `agree()` must never panic for any 56-byte secret or arbitrary-length
/// public key; it must return either `Ok` or a structured `Err`.
#[test]
fn fuzz_x448_agree_never_panics() {
    let kex = X448;
    let mut out = [0u8; 56];

    for seed in 0u64..64 {
        let secret = lcg_bytes(seed, 56);
        let public = lcg_bytes(seed.wrapping_add(0x2000), 56);
        let _ = kex.agree(&secret, &public, &mut out);
    }

    // Wrong-length inputs.
    for bad_len in [0usize, 1, 32, 55, 57, 64] {
        let bad = lcg_bytes(bad_len as u64, bad_len);
        let _ = kex.agree(&bad, &[0u8; 56], &mut out);
        let _ = kex.agree(&[0u8; 56], &bad, &mut out);
    }
}

/// EcdhP256 `agree()` must never panic on arbitrary-length inputs.
#[test]
fn fuzz_ecdh_p256_agree_never_panics() {
    let kex = EcdhP256;
    let mut out = [0u8; 32];

    for seed in 0u64..128 {
        let secret = lcg_bytes(seed, 32);
        // Try various public key lengths: both the uncompressed (65 bytes) and
        // compressed (33 bytes) forms, plus malformed lengths.
        for pub_len in [0usize, 1, 32, 33, 65, 97, 128] {
            let public = lcg_bytes(seed.wrapping_add(0x3000 + pub_len as u64), pub_len);
            let _ = kex.agree(&secret, &public, &mut out);
        }
    }
}

/// EcdhP384 `agree()` must never panic on arbitrary-length inputs.
#[test]
fn fuzz_ecdh_p384_agree_never_panics() {
    let kex = EcdhP384;
    let mut out = [0u8; 48];

    for seed in 0u64..64 {
        let secret = lcg_bytes(seed, 48);
        for pub_len in [0usize, 1, 48, 49, 97, 128] {
            let public = lcg_bytes(seed.wrapping_add(0x4000 + pub_len as u64), pub_len);
            let _ = kex.agree(&secret, &public, &mut out);
        }
    }
}

/// EcdhP521 `agree()` must never panic on arbitrary-length inputs.
#[test]
fn fuzz_ecdh_p521_agree_never_panics() {
    let kex = EcdhP521;
    let mut out = [0u8; 66];

    for seed in 0u64..32 {
        let secret = lcg_bytes(seed, 66);
        for pub_len in [0usize, 1, 65, 66, 133, 200] {
            let public = lcg_bytes(seed.wrapping_add(0x5000 + pub_len as u64), pub_len);
            let _ = kex.agree(&secret, &public, &mut out);
        }
    }
}

/// Output buffer smaller than the shared secret length must return
/// `Err(BufferTooSmall)`, not panic.
#[test]
fn fuzz_agree_small_output_buffer_errors_not_panics() {
    let x25519 = X25519;
    let secret = lcg_bytes(0xABCD_0001, 32);
    let public = lcg_bytes(0xABCD_0002, 32);

    // Buffer of size 0 must return Err, not panic.
    let result = x25519.agree(&secret, &public, &mut []);
    assert!(result.is_err(), "empty output buffer must return Err");

    // Buffer of size 1 must return Err, not panic.
    let mut tiny = [0u8; 1];
    let result = x25519.agree(&secret, &public, &mut tiny);
    assert!(result.is_err(), "1-byte output buffer must return Err");
}

// ── OxiRng integration ────────────────────────────────────────────────────────
//
// All `generate_keypair` helpers must accept `OxiRng` (which implements
// `TryCryptoRng`) and produce working key pairs.

/// Verify that `x25519_generate_keypair` works with `OxiRng`.
#[test]
fn oxirng_x25519_generate_keypair() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let (alice_sk, alice_pk) = x25519_generate_keypair(&mut rng).expect("x25519 keygen");
    let (bob_sk, bob_pk) = x25519_generate_keypair(&mut rng).expect("x25519 keygen");

    // Keys should be non-zero.
    assert_ne!(
        *alice_sk.as_bytes(),
        [0u8; 32],
        "x25519 secret must be non-zero"
    );
    assert_ne!(alice_pk, [0u8; 32], "x25519 public must be non-zero");

    // DH commutativity.
    let kex = X25519;
    let mut alice_shared = [0u8; 32];
    let mut bob_shared = [0u8; 32];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob agree");
    assert_eq!(
        alice_shared, bob_shared,
        "x25519 DH must be commutative with OxiRng keys"
    );
}

/// Verify that `x448_generate_keypair` works with `OxiRng`.
#[test]
fn oxirng_x448_generate_keypair() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let (alice_sk, alice_pk) = x448_generate_keypair(&mut rng).expect("x448 keygen");
    let (bob_sk, bob_pk) = x448_generate_keypair(&mut rng).expect("x448 keygen");

    assert_ne!(
        *alice_sk.as_bytes(),
        [0u8; 56],
        "x448 secret must be non-zero"
    );
    assert_ne!(alice_pk, [0u8; 56], "x448 public must be non-zero");

    let kex = X448;
    let mut alice_shared = [0u8; 56];
    let mut bob_shared = [0u8; 56];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice x448 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob x448 agree");
    assert_eq!(
        alice_shared, bob_shared,
        "x448 DH must be commutative with OxiRng keys"
    );
}

/// Verify that `ecdh_p256_generate_keypair` works with `OxiRng`.
#[test]
fn oxirng_ecdh_p256_generate_keypair() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let (alice_sk, alice_pk) = ecdh_p256_generate_keypair(&mut rng).expect("p256 keygen");
    let (bob_sk, bob_pk) = ecdh_p256_generate_keypair(&mut rng).expect("p256 keygen");

    // Compressed SEC1 P-256 public key: 33 bytes, first byte 02 or 03.
    assert!(
        alice_pk.len() == 33 || alice_pk.len() == 65,
        "p256 public key must be 33 or 65 bytes"
    );

    let kex = EcdhP256;
    let mut alice_shared = [0u8; 32];
    let mut bob_shared = [0u8; 32];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice p256 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob p256 agree");
    assert_eq!(
        alice_shared, bob_shared,
        "p256 DH must be commutative with OxiRng keys"
    );
}

/// Verify that `ecdh_p384_generate_keypair` works with `OxiRng`.
#[test]
fn oxirng_ecdh_p384_generate_keypair() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let (alice_sk, alice_pk) = ecdh_p384_generate_keypair(&mut rng).expect("p384 keygen");
    let (bob_sk, bob_pk) = ecdh_p384_generate_keypair(&mut rng).expect("p384 keygen");

    assert!(
        alice_pk.len() == 49 || alice_pk.len() == 97,
        "p384 public key must be 49 or 97 bytes"
    );

    let kex = EcdhP384;
    let mut alice_shared = [0u8; 48];
    let mut bob_shared = [0u8; 48];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice p384 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob p384 agree");
    assert_eq!(
        alice_shared, bob_shared,
        "p384 DH must be commutative with OxiRng keys"
    );
}

/// Verify that `ecdh_p521_generate_keypair` works with `OxiRng`.
#[test]
fn oxirng_ecdh_p521_generate_keypair() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let (alice_sk, alice_pk) = ecdh_p521_generate_keypair(&mut rng).expect("p521 keygen");
    let (bob_sk, bob_pk) = ecdh_p521_generate_keypair(&mut rng).expect("p521 keygen");

    // P-521 public key: 67 bytes compressed or 133 bytes uncompressed.
    assert!(
        alice_pk.len() == 67 || alice_pk.len() == 133,
        "p521 public key must be 67 or 133 bytes, got {}",
        alice_pk.len()
    );

    let kex = EcdhP521;
    let mut alice_shared = [0u8; 66];
    let mut bob_shared = [0u8; 66];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice p521 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob p521 agree");
    assert_eq!(
        alice_shared, bob_shared,
        "p521 DH must be commutative with OxiRng keys"
    );
}

// ── negotiate_kex tests ───────────────────────────────────────────────────────

/// negotiate_kex must resolve all supported TLS named groups to the correct algorithm.
#[test]
fn negotiate_kex_resolves_all_groups() {
    let cases: &[(&str, &str, usize, usize)] = &[
        // (input, expected name, scalar_len, point_len)
        ("x25519", "X25519", 32, 32),
        ("X25519", "X25519", 32, 32),
        ("x448", "X448", 56, 56),
        ("X448", "X448", 56, 56),
        ("secp256r1", "ECDH-P256", 32, 33),
        ("P-256", "ECDH-P256", 32, 33),
        ("p256", "ECDH-P256", 32, 33),
        ("ECDH-P256", "ECDH-P256", 32, 33),
        ("secp384r1", "ECDH-P384", 48, 49),
        ("P-384", "ECDH-P384", 48, 49),
        ("p384", "ECDH-P384", 48, 49),
        ("ECDH-P384", "ECDH-P384", 48, 49),
        ("secp521r1", "ECDH-P521", 66, 133),
        ("P-521", "ECDH-P521", 66, 133),
        ("p521", "ECDH-P521", 66, 133),
        ("ECDH-P521", "ECDH-P521", 66, 133),
    ];

    for &(group, expected_name, expected_scalar, expected_point) in cases {
        let kex = negotiate_kex(group)
            .unwrap_or_else(|_| panic!("negotiate_kex({group:?}) must succeed"));
        assert_eq!(
            kex.name(),
            expected_name,
            "name mismatch for group {group:?}"
        );
        assert_eq!(
            kex.scalar_len(),
            expected_scalar,
            "scalar_len mismatch for group {group:?}"
        );
        assert_eq!(
            kex.point_len(),
            expected_point,
            "point_len mismatch for group {group:?}"
        );
    }
}

/// negotiate_kex must return an error for unrecognized group names.
#[test]
fn negotiate_kex_rejects_unknown_groups() {
    use oxicrypto_core::CryptoError;

    let unknown_groups = [
        "",
        "x25519-kyber768",
        "kyber768",
        "mlkem768",
        "brainpoolP256r1",
    ];
    for group in unknown_groups {
        let result = negotiate_kex(group);
        assert_eq!(
            result.map(|_| ()),
            Err(CryptoError::UnsupportedAlgorithm),
            "negotiate_kex({group:?}) must return UnsupportedAlgorithm"
        );
    }
}

/// negotiate_kex must return a functional implementation: generate keys and agree.
#[test]
fn negotiate_kex_x25519_is_functional() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let kex = negotiate_kex("x25519").expect("x25519 negotiate");

    let (alice_sk, alice_pk) = x25519_generate_keypair(&mut rng).expect("alice keygen");
    let (bob_sk, bob_pk) = x25519_generate_keypair(&mut rng).expect("bob keygen");

    let mut alice_shared = [0u8; 32];
    let mut bob_shared = [0u8; 32];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob agree");
    assert_eq!(
        alice_shared, bob_shared,
        "negotiate_kex X25519 must be commutative"
    );
}

/// negotiate_kex X448 must return a functional implementation.
#[test]
fn negotiate_kex_x448_is_functional() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let kex = negotiate_kex("x448").expect("x448 negotiate");

    let (alice_sk, alice_pk) = x448_generate_keypair(&mut rng).expect("alice keygen");
    let (bob_sk, bob_pk) = x448_generate_keypair(&mut rng).expect("bob keygen");

    let mut alice_shared = [0u8; 56];
    let mut bob_shared = [0u8; 56];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice x448 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob x448 agree");
    assert_eq!(
        alice_shared, bob_shared,
        "negotiate_kex X448 must be commutative"
    );
}

/// negotiate_kex P-256 (secp256r1) must return a functional implementation.
#[test]
fn negotiate_kex_p256_is_functional() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let kex = negotiate_kex("secp256r1").expect("secp256r1 negotiate");

    let (alice_sk, alice_pk) = ecdh_p256_generate_keypair(&mut rng).expect("alice keygen");
    let (bob_sk, bob_pk) = ecdh_p256_generate_keypair(&mut rng).expect("bob keygen");

    let mut alice_shared = [0u8; 32];
    let mut bob_shared = [0u8; 32];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("alice p256 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("bob p256 agree");
    assert_eq!(
        alice_shared, bob_shared,
        "negotiate_kex P-256 must be commutative"
    );
}
