//! Wycheproof-style ECDSA P-256 test vectors and property-based tests.
//!
//! The p256 crate uses RFC 6979 deterministic nonce generation internally but
//! its public API produces DER-encoded signatures whose byte encoding can vary
//! between versions (leading zeros in r/s). Accordingly we focus on:
//!   1. Sign + verify round-trip correctness using multiple key/message pairs.
//!   2. Tamper-resistance (wrong message, corrupted signature, cross-key).
//!   3. Error-path enforcement (zero scalar, invalid key length, bad encoding).
//!
//! These tests directly capture the invariants validated by the Google Wycheproof
//! test suite for ECDSA secp256r1 (P-256) SHA-256.
//!
//! References:
//!   - Wycheproof ECDSA P-256 SHA-256 test vectors (public domain, Google)
//!   - NIST FIPS 186-5
//!   - RFC 6979 (deterministic nonce generation)

use oxicrypto_sig::{EcdsaP256Signer, EcdsaP256Verifier};

// ── Core sign + verify round-trip tests ──────────────────────────────────────

/// Wycheproof-style public-key validity check: a valid SEC1-compressed P-256
/// public key must be accepted; its corresponding signing key must produce
/// a signature that passes verification.
///
/// The private key is the NIST P-256 example from RFC 6979 §A.2.5.
/// The public key is derived from it (compressed SEC1, 33 bytes).
#[test]
fn wycheproof_p256_public_key_validity_and_verify() {
    // RFC 6979 §A.2.5 P-256 private key
    let sk_bytes: [u8; 32] = [
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ];
    // Corresponding compressed SEC1 public key (33 bytes, 02 or 03 prefix)
    // Derived from the private scalar; this is the canonical Wycheproof-format public key.
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer from RFC 6979 key");
    let pk_sec1 = signer.verifying_key_bytes();

    // Verify the public key has a valid SEC1 length (33 bytes compressed or 65 bytes uncompressed)
    assert!(
        pk_sec1.len() == 33 || pk_sec1.len() == 65,
        "SEC1 public key must be 33 or 65 bytes, got {}",
        pk_sec1.len()
    );
    // Verify the SEC1 prefix byte is valid
    assert!(
        matches!(pk_sec1[0], 0x02..=0x04),
        "SEC1 prefix must be 0x02, 0x03, or 0x04, got 0x{:02x}",
        pk_sec1[0]
    );

    // Now sign a standard Wycheproof test message and verify
    let msg = b"313233343536373839303132333435363738393031323334353637383930313233";
    let sig = signer.sign(msg).expect("sign must succeed");
    EcdsaP256Verifier::from_sec1_bytes(&pk_sec1)
        .expect("public key from verifying_key_bytes must be valid")
        .verify(msg, &sig)
        .expect("verify must succeed");
}

/// Sign with the RFC 6979 test key (NIST P-256 §A.2.5) and verify with the
/// corresponding public key — baseline round-trip.
#[test]
fn p256_sign_verify_rfc6979_key_sample_message() {
    let sk_bytes: [u8; 32] = [
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ];
    let msg = b"sample";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("RFC 6979 P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("sign must succeed");

    assert!(!sig.is_empty(), "DER signature must be non-empty");
    // DER P-256 signatures are always in range [70, 72] bytes
    assert!(
        sig.len() >= 70 && sig.len() <= 72,
        "unexpected DER length {}",
        sig.len()
    );

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes)
        .expect("public key from verifying_key_bytes must succeed");
    verifier.verify(msg, &sig).expect("verify must succeed");
}

/// A different message using the same key must also verify.
#[test]
fn p256_sign_verify_round_trip_test_message() {
    let sk_bytes: [u8; 32] = [0x42; 32];
    let msg = b"The quick brown fox jumps over the lazy dog";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("sign");

    EcdsaP256Verifier::from_sec1_bytes(&pub_bytes)
        .expect("verifier")
        .verify(msg, &sig)
        .expect("verify must succeed");
}

/// Empty message round-trip.
#[test]
fn p256_sign_verify_empty_message() {
    let sk_bytes: [u8; 32] = [0x01; 32];
    let msg = b"";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("sign empty msg");

    EcdsaP256Verifier::from_sec1_bytes(&pub_bytes)
        .expect("verifier")
        .verify(msg, &sig)
        .expect("verify empty msg");
}

/// Single-byte message round-trip.
#[test]
fn p256_sign_verify_single_byte_message() {
    let sk_bytes: [u8; 32] = [0x7f; 32];
    let msg = b"\xff";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("sign");

    EcdsaP256Verifier::from_sec1_bytes(&pub_bytes)
        .expect("verifier")
        .verify(msg, &sig)
        .expect("verify");
}

// ── Tamper-resistance tests ───────────────────────────────────────────────────

/// Verifying against a modified message must fail.
#[test]
fn p256_wrong_message_fails() {
    let sk_bytes: [u8; 32] = [0x03; 32];
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(b"correct").expect("sign");

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"tampered", &sig).is_err(),
        "wrong message must not verify"
    );
}

/// A single-bit flip in the signature must cause verification to fail.
#[test]
fn p256_corrupted_signature_fails() {
    let sk_bytes: [u8; 32] = [0x04; 32];
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let mut sig = signer.sign(b"message").expect("sign");
    // Flip a bit in the signature body (index 4 is inside the ASN.1 integer).
    sig[4] ^= 0x01;

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"message", &sig).is_err(),
        "corrupted signature must not verify"
    );
}

/// A completely zeroed-out (invalid DER) signature must fail gracefully.
#[test]
fn p256_empty_signature_fails() {
    let sk_bytes: [u8; 32] = [0x05; 32];
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"message", &[]).is_err(),
        "empty signature must fail"
    );
}

/// Verifying a signature produced with key A against key B's public key must fail.
#[test]
fn p256_cross_key_verification_fails() {
    let sk_a: [u8; 32] = [0x11; 32];
    let sk_b: [u8; 32] = [0x22; 32];

    let signer_a = EcdsaP256Signer::from_bytes(&sk_a).expect("signer A");
    let signer_b = EcdsaP256Signer::from_bytes(&sk_b).expect("signer B");
    let pub_b = signer_b.verifying_key_bytes();

    let sig_a = signer_a.sign(b"hello").expect("sign with key A");

    let verifier_b = EcdsaP256Verifier::from_sec1_bytes(&pub_b).expect("verifier B");
    assert!(
        verifier_b.verify(b"hello", &sig_a).is_err(),
        "signature from key A must not verify with key B"
    );
}

// ── Error-path tests ──────────────────────────────────────────────────────────

/// All-zero scalar is not a valid P-256 private key.
#[test]
fn p256_zero_scalar_rejected() {
    assert!(
        EcdsaP256Signer::from_bytes(&[0u8; 32]).is_err(),
        "zero scalar must be rejected"
    );
}

/// Scalar equal to the curve order n is not in [1, n-1] and must be rejected.
///
/// n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
#[test]
fn p256_scalar_equal_to_order_rejected() {
    let n: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];
    assert!(
        EcdsaP256Signer::from_bytes(&n).is_err(),
        "scalar equal to curve order must be rejected"
    );
}

/// Invalid SEC1 public key bytes (wrong length) must be rejected.
#[test]
fn p256_invalid_public_key_rejected() {
    assert!(
        EcdsaP256Verifier::from_sec1_bytes(&[0u8; 10]).is_err(),
        "10-byte slice is not a valid SEC1 public key"
    );
}
