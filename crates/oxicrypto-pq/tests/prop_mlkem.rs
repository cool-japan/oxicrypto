//! ML-KEM (FIPS 203) property-based tests.
//!
//! These tests exercise invariants that must hold across random inputs:
//! - encapsulate → decapsulate always recovers the same shared secret.
//! - A single-bit flip in the ciphertext produces a different shared secret
//!   (ML-KEM uses implicit rejection, so decap never panics).
//! - Key serialization round-trips: `from_bytes(to_bytes(k))` produces an
//!   equivalent key.

use oxicrypto_pq::mlkem::{
    Ciphertext512, Ciphertext768, DecapKey512, DecapKey768, EncapKey512, EncapKey768, MlKem1024,
    MlKem512, MlKem768,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-512 property tests
// ─────────────────────────────────────────────────────────────────────────────

/// Property: encapsulate → decapsulate always recovers the same shared secret.
#[test]
fn prop_mlkem512_encap_decap_round_trip() {
    for i in 0u8..3 {
        let mut rng = ChaCha20Rng::from_seed([i; 32]);
        let (dk, ek) = MlKem512::generate(&mut rng);

        let ek_bytes = ek.to_bytes();
        let ek2 = EncapKey512::from_bytes(&ek_bytes).expect("EncapKey512::from_bytes");

        let (ct, ss_encap) = ek2.encapsulate(&mut rng).expect("encapsulate");
        let ct_bytes = ct.to_bytes();
        let ct2 = Ciphertext512::from_bytes(&ct_bytes).expect("Ciphertext512::from_bytes");

        let dk_seed = dk.to_bytes().expect("DecapKey512::to_bytes");
        let dk2 = DecapKey512::from_bytes(&dk_seed).expect("DecapKey512::from_bytes");
        let ss_decap = dk2.decapsulate(&ct2).expect("decapsulate");

        assert_eq!(
            ss_encap.as_slice(),
            ss_decap.as_slice(),
            "iter {i}: ML-KEM-512 shared secrets must match"
        );
    }
}

/// Property: modifying a single byte of the ciphertext produces a different shared secret.
///
/// ML-KEM uses implicit rejection: decapsulation never fails, but returns a
/// pseudorandom value derived from a secret "rejection seed" when the ciphertext
/// is malformed.  The result must differ from the original.
#[test]
fn prop_mlkem512_tampered_ciphertext_produces_different_ss() {
    let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
    let (dk, ek) = MlKem512::generate(&mut rng);
    let (ct, ss_correct) = ek.encapsulate(&mut rng).expect("encapsulate");

    let mut ct_bytes = ct.to_bytes();
    ct_bytes[0] ^= 0x01;

    let ct_tampered = Ciphertext512::from_bytes(&ct_bytes).expect("from_bytes on tampered CT");
    let ss_wrong = dk.decapsulate(&ct_tampered).expect("decap should not fail");

    assert_ne!(
        ss_correct.as_slice(),
        ss_wrong.as_slice(),
        "tampered CT must produce different shared secret (implicit rejection)"
    );
}

/// Property: key serialization round-trips.
#[test]
fn test_mlkem512_key_serialization_round_trip() {
    let mut rng = ChaCha20Rng::from_seed([0x11u8; 32]);
    let (dk, ek) = MlKem512::generate(&mut rng);

    let ek_bytes = ek.to_bytes();
    assert_eq!(ek_bytes.len(), MlKem512::ENCAP_KEY_LEN);

    let dk_seed = dk.to_bytes().expect("to_bytes");
    // Seed is 64 bytes (compact representation).
    assert_eq!(dk_seed.len(), 64);

    let ek2 = EncapKey512::from_bytes(&ek_bytes).expect("EncapKey512::from_bytes");
    assert_eq!(
        ek2.to_bytes(),
        ek_bytes,
        "encap key round-trip must be exact"
    );

    // Verify the deserialized decap key still decapsulates correctly.
    let dk2 = DecapKey512::from_bytes(&dk_seed).expect("DecapKey512::from_bytes");
    let (ct, ss1) = ek2.encapsulate(&mut rng).expect("encapsulate");
    let ss2 = dk2.decapsulate(&ct).expect("decapsulate");
    assert_eq!(
        ss1.as_slice(),
        ss2.as_slice(),
        "deserialized keys must produce matching shared secrets"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-768 property tests
// ─────────────────────────────────────────────────────────────────────────────

/// Property: encapsulate → decapsulate always recovers the same shared secret.
#[test]
fn prop_mlkem768_encap_decap_round_trip() {
    for i in 0u8..5 {
        let mut rng = ChaCha20Rng::from_seed([i; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);

        let ek_bytes = ek.to_bytes();
        let ek2 = EncapKey768::from_bytes(&ek_bytes).expect("EncapKey768::from_bytes");

        let (ct, ss_encap) = ek2.encapsulate(&mut rng).expect("encapsulate");
        let ct_bytes = ct.to_bytes();
        let ct2 = Ciphertext768::from_bytes(&ct_bytes).expect("Ciphertext768::from_bytes");

        let dk_seed = dk.to_bytes().expect("DecapKey768::to_bytes");
        let dk2 = DecapKey768::from_bytes(&dk_seed).expect("DecapKey768::from_bytes");
        let ss_decap = dk2.decapsulate(&ct2).expect("decapsulate");

        assert_eq!(
            ss_encap.as_slice(),
            ss_decap.as_slice(),
            "iter {i}: ML-KEM-768 shared secrets must match"
        );
    }
}

/// Property: modifying a single byte of the ciphertext produces a different shared secret.
#[test]
fn prop_mlkem768_tampered_ciphertext_produces_different_ss() {
    let mut rng = ChaCha20Rng::from_seed([0x77u8; 32]);
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, ss_correct) = ek.encapsulate(&mut rng).expect("encapsulate");

    let mut ct_bytes = ct.to_bytes();
    ct_bytes[0] ^= 0x01;

    let ct_tampered = Ciphertext768::from_bytes(&ct_bytes).expect("from_bytes on tampered CT");
    let ss_wrong = dk.decapsulate(&ct_tampered).expect("decap should not fail");

    assert_ne!(
        ss_correct.as_slice(),
        ss_wrong.as_slice(),
        "tampered CT must produce different shared secret (implicit rejection)"
    );
}

/// Property: key serialization round-trips.
#[test]
fn test_mlkem768_key_serialization_round_trip() {
    let mut rng = ChaCha20Rng::from_seed([0x22u8; 32]);
    let (dk, ek) = MlKem768::generate(&mut rng);

    let ek_bytes = ek.to_bytes();
    assert_eq!(ek_bytes.len(), MlKem768::ENCAP_KEY_LEN);

    let dk_seed = dk.to_bytes().expect("to_bytes");
    assert_eq!(dk_seed.len(), 64);

    let ek2 = EncapKey768::from_bytes(&ek_bytes).expect("EncapKey768::from_bytes");
    assert_eq!(
        ek2.to_bytes(),
        ek_bytes,
        "encap key round-trip must be exact"
    );

    let dk2 = DecapKey768::from_bytes(&dk_seed).expect("DecapKey768::from_bytes");
    let (ct, ss1) = ek2.encapsulate(&mut rng).expect("encapsulate");
    let ss2 = dk2.decapsulate(&ct).expect("decapsulate");
    assert_eq!(
        ss1.as_slice(),
        ss2.as_slice(),
        "deserialized keys must produce matching shared secrets"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-1024 property tests  (marked #[ignore] — same guarantees as 768
//  but slower; run explicitly with `cargo test -- --ignored`).
// ─────────────────────────────────────────────────────────────────────────────

/// Property: encapsulate → decapsulate always recovers the same shared secret.
#[test]
#[ignore = "ML-KEM-1024 is slower; run explicitly with --include-ignored"]
fn prop_mlkem1024_encap_decap_round_trip() {
    use oxicrypto_pq::mlkem::{Ciphertext1024, DecapKey1024, EncapKey1024};

    for i in 0u8..3 {
        let mut rng = ChaCha20Rng::from_seed([i; 32]);
        let (dk, ek) = MlKem1024::generate(&mut rng);

        let ek_bytes = ek.to_bytes();
        let ek2 = EncapKey1024::from_bytes(&ek_bytes).expect("from_bytes");

        let (ct, ss_encap) = ek2.encapsulate(&mut rng).expect("encapsulate");
        let ct_bytes = ct.to_bytes();
        let ct2 = Ciphertext1024::from_bytes(&ct_bytes).expect("from_bytes");

        let dk_seed = dk.to_bytes().expect("to_bytes");
        let dk2 = DecapKey1024::from_bytes(&dk_seed).expect("from_bytes");
        let ss_decap = dk2.decapsulate(&ct2).expect("decapsulate");

        assert_eq!(
            ss_encap.as_slice(),
            ss_decap.as_slice(),
            "iter {i}: ML-KEM-1024 shared secrets must match"
        );
    }
}

/// Property: ML-KEM-1024 key serialization round-trips.
#[test]
#[ignore = "ML-KEM-1024 is slower; run explicitly with --include-ignored"]
fn test_mlkem1024_key_serialization_round_trip() {
    use oxicrypto_pq::mlkem::{DecapKey1024, EncapKey1024};

    let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
    let (dk, ek) = MlKem1024::generate(&mut rng);

    let ek_bytes = ek.to_bytes();
    assert_eq!(ek_bytes.len(), MlKem1024::ENCAP_KEY_LEN);

    let dk_seed = dk.to_bytes().expect("to_bytes");
    assert_eq!(dk_seed.len(), 64);

    let ek2 = EncapKey1024::from_bytes(&ek_bytes).expect("from_bytes");
    assert_eq!(ek2.to_bytes(), ek_bytes);

    let dk2 = DecapKey1024::from_bytes(&dk_seed).expect("from_bytes");
    let (ct, ss1) = ek2.encapsulate(&mut rng).expect("encapsulate");
    let ss2 = dk2.decapsulate(&ct).expect("decapsulate");
    assert_eq!(ss1.as_slice(), ss2.as_slice());
}
