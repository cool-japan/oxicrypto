//! Property-based tests for OxiCrypto signature algorithms.
//!
//! These tests verify the fundamental sign→verify correctness property:
//! for any key pair and any message, `verify(pk, msg, sign(sk, msg))` must succeed.
//!
//! Additional properties tested:
//! - Signing with one key and verifying with a different key must fail.
//! - Signing a message and verifying against a different message must fail.
//! - Random signatures (not produced by sign) must be rejected (with overwhelmingly high probability).

use oxicrypto_core::{CryptoError, Signer as _, Verifier as _};
use oxicrypto_rand::OxiRng;
use oxicrypto_sig::{
    ecdsa_p256_generate_keypair, ecdsa_p384_generate_keypair, ecdsa_p521_generate_keypair,
    ed25519_generate_keypair,
    ed448_ext::{ed448ctx_sign, ed448ctx_verify, ed448ph_sign, ed448ph_verify},
    rsa_sig::{rsa_oaep_sha256_decrypt, rsa_oaep_sha256_encrypt},
    EcdsaP256, EcdsaP256Verify, EcdsaP384, EcdsaP384Verify, EcdsaP521, EcdsaP521Verify, Ed25519,
    Ed25519Verifier,
};

// ── Ed25519 property tests ────────────────────────────────────────────────────

/// Property: sign(sk, msg) followed by verify(pk, msg, sig) always succeeds.
#[test]
fn prop_ed25519_sign_verify_succeeds() {
    let mut rng = OxiRng::new().expect("rng");
    for _ in 0..10 {
        let (sk, pk) = ed25519_generate_keypair(&mut rng).expect("keygen");

        let signer = Ed25519;
        let verifier = Ed25519Verifier;

        let msg = b"property test: ed25519 sign/verify correctness";
        let mut sig = [0u8; 64];
        signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");
        verifier.verify(&pk, msg, &sig).expect("verify");
    }
}

/// Property: verify with wrong message fails.
#[test]
fn prop_ed25519_wrong_message_fails() {
    let mut rng = OxiRng::new().expect("rng");
    let (sk, pk) = ed25519_generate_keypair(&mut rng).expect("keygen");

    let signer = Ed25519;
    let verifier = Ed25519Verifier;

    let msg = b"original message";
    let wrong_msg = b"tampered message!";

    let mut sig = [0u8; 64];
    signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");

    let result = verifier.verify(&pk, wrong_msg, &sig);
    assert!(result.is_err(), "wrong message should not verify");
}

/// Property: verify with wrong key fails.
#[test]
fn prop_ed25519_wrong_key_fails() {
    let mut rng = OxiRng::new().expect("rng");
    let (sk, _pk) = ed25519_generate_keypair(&mut rng).expect("keygen");
    let (_other_sk, other_pk) = ed25519_generate_keypair(&mut rng).expect("keygen other");

    let signer = Ed25519;
    let verifier = Ed25519Verifier;

    let msg = b"ed25519 wrong-key test";
    let mut sig = [0u8; 64];
    signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");

    let result = verifier.verify(&other_pk, msg, &sig);
    assert!(result.is_err(), "wrong public key should not verify");
}

/// Property: verify with random bytes as signature does not panic and almost always fails.
///
/// There is a 1-in-2^252 probability of a random 64-byte blob being a valid signature;
/// we simply check that this call does not panic.
#[test]
fn prop_ed25519_random_sig_no_panic() {
    use rand_core::TryRng;
    let mut rng = OxiRng::new().expect("rng");
    let (_sk, pk) = ed25519_generate_keypair(&mut rng).expect("keygen");
    let verifier = Ed25519Verifier;

    for _ in 0..5 {
        let mut random_sig = [0u8; 64];
        rng.try_fill_bytes(&mut random_sig).expect("fill");
        // Should not panic; may return Ok or Err
        let _ = verifier.verify(&pk, b"test message", &random_sig);
    }
}

// ── ECDSA P-256 property tests ────────────────────────────────────────────────

/// Property: sign(sk, msg) followed by verify(pk, msg, sig) always succeeds for ECDSA P-256.
#[test]
fn prop_ecdsa_p256_sign_verify_succeeds() {
    let mut rng = OxiRng::new().expect("rng");
    for _ in 0..5 {
        let (sk, pk) = ecdsa_p256_generate_keypair(&mut rng).expect("keygen");

        let signer = EcdsaP256;
        let verifier = EcdsaP256Verify;

        let msg = b"property test: ecdsa-p256 sign/verify correctness";
        let mut sig = [0u8; 72];
        let len = signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");
        verifier.verify(&pk, msg, &sig[..len]).expect("verify");
    }
}

/// Property: ECDSA P-256 verify with wrong message fails.
#[test]
fn prop_ecdsa_p256_wrong_message_fails() {
    let mut rng = OxiRng::new().expect("rng");
    let (sk, pk) = ecdsa_p256_generate_keypair(&mut rng).expect("keygen");

    let signer = EcdsaP256;
    let verifier = EcdsaP256Verify;

    let msg = b"original message";
    let wrong_msg = b"different message";

    let mut sig = [0u8; 72];
    let len = signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");

    let result = verifier.verify(&pk, wrong_msg, &sig[..len]);
    assert!(result.is_err(), "wrong message should not verify");
}

/// Property: ECDSA P-256 verify with wrong key fails.
#[test]
fn prop_ecdsa_p256_wrong_key_fails() {
    let mut rng = OxiRng::new().expect("rng");
    let (sk, _pk) = ecdsa_p256_generate_keypair(&mut rng).expect("keygen");
    let (_other_sk, other_pk) = ecdsa_p256_generate_keypair(&mut rng).expect("keygen other");

    let signer = EcdsaP256;
    let verifier = EcdsaP256Verify;

    let msg = b"ecdsa-p256 wrong-key test";
    let mut sig = [0u8; 72];
    let len = signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");

    let result = verifier.verify(&other_pk, msg, &sig[..len]);
    assert!(result.is_err(), "wrong public key should not verify");
}

// ── ECDSA P-384 property tests ────────────────────────────────────────────────

/// Property: sign/verify correctness for ECDSA P-384.
#[test]
fn prop_ecdsa_p384_sign_verify_succeeds() {
    let mut rng = OxiRng::new().expect("rng");
    for _ in 0..5 {
        let (sk, pk) = ecdsa_p384_generate_keypair(&mut rng).expect("keygen");

        let signer = EcdsaP384;
        let verifier = EcdsaP384Verify;

        let msg = b"property test: ecdsa-p384 sign/verify correctness";
        let mut sig = [0u8; 104];
        let len = signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");
        verifier.verify(&pk, msg, &sig[..len]).expect("verify");
    }
}

/// Property: ECDSA P-384 wrong key fails.
#[test]
fn prop_ecdsa_p384_wrong_key_fails() {
    let mut rng = OxiRng::new().expect("rng");
    let (sk, _pk) = ecdsa_p384_generate_keypair(&mut rng).expect("keygen");
    let (_other_sk, other_pk) = ecdsa_p384_generate_keypair(&mut rng).expect("keygen other");

    let signer = EcdsaP384;
    let verifier = EcdsaP384Verify;

    let msg = b"ecdsa-p384 wrong-key test";
    let mut sig = [0u8; 104];
    let len = signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");

    let result = verifier.verify(&other_pk, msg, &sig[..len]);
    assert!(result.is_err(), "wrong public key should not verify");
}

// ── ECDSA P-521 property tests ────────────────────────────────────────────────

/// Property: sign/verify correctness for ECDSA P-521.
#[test]
fn prop_ecdsa_p521_sign_verify_succeeds() {
    let mut rng = OxiRng::new().expect("rng");
    for _ in 0..5 {
        let (sk, pk) = ecdsa_p521_generate_keypair(&mut rng).expect("keygen");

        let signer = EcdsaP521;
        let verifier = EcdsaP521Verify;

        let msg = b"property test: ecdsa-p521 sign/verify correctness";
        let mut sig = [0u8; 139];
        let len = signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");
        verifier.verify(&pk, msg, &sig[..len]).expect("verify");
    }
}

/// Property: ECDSA P-521 wrong message fails.
#[test]
fn prop_ecdsa_p521_wrong_message_fails() {
    let mut rng = OxiRng::new().expect("rng");
    let (sk, pk) = ecdsa_p521_generate_keypair(&mut rng).expect("keygen");

    let signer = EcdsaP521;
    let verifier = EcdsaP521Verify;

    let msg = b"original message";
    let wrong_msg = b"different content";

    let mut sig = [0u8; 139];
    let len = signer.sign(sk.as_bytes(), msg, &mut sig).expect("sign");

    let result = verifier.verify(&pk, wrong_msg, &sig[..len]);
    assert!(result.is_err(), "wrong message should not verify");
}

// ── Ed448ph property tests ────────────────────────────────────────────────────

/// Property: Ed448ph sign/verify succeeds without context.
#[test]
fn prop_ed448ph_sign_verify_no_context() {
    // Use a fixed seed for a deterministic test key
    let sk_seed = [0x1Fu8; 57];
    let sk_signing = oxicrypto_sig::Ed448SigningKey::from_bytes(&sk_seed).expect("ed448 sk");
    let pk_bytes = sk_signing.verifying_key_bytes();

    let msg = b"property test: ed448ph sign/verify without context";
    let sig = ed448ph_sign(&sk_seed, msg, None).expect("ed448ph sign");
    ed448ph_verify(&pk_bytes, msg, &sig, None).expect("ed448ph verify");
}

/// Property: Ed448ph sign/verify succeeds with a context string.
#[test]
fn prop_ed448ph_sign_verify_with_context() {
    let sk_seed = [0x2Eu8; 57];
    let sk_signing = oxicrypto_sig::Ed448SigningKey::from_bytes(&sk_seed).expect("ed448 sk");
    let pk_bytes = sk_signing.verifying_key_bytes();
    let ctx = b"test-protocol-v1";

    let msg = b"property test: ed448ph sign/verify with context";
    let sig = ed448ph_sign(&sk_seed, msg, Some(ctx)).expect("ed448ph sign");
    ed448ph_verify(&pk_bytes, msg, &sig, Some(ctx)).expect("ed448ph verify");
}

/// Property: Ed448ph verify with wrong context fails.
#[test]
fn prop_ed448ph_wrong_context_fails() {
    let sk_seed = [0x3Du8; 57];
    let sk_signing = oxicrypto_sig::Ed448SigningKey::from_bytes(&sk_seed).expect("ed448 sk");
    let pk_bytes = sk_signing.verifying_key_bytes();
    let ctx = b"original-context";
    let wrong_ctx = b"different-context";

    let msg = b"ed448ph context isolation test";
    let sig = ed448ph_sign(&sk_seed, msg, Some(ctx)).expect("ed448ph sign");
    let result = ed448ph_verify(&pk_bytes, msg, &sig, Some(wrong_ctx));
    assert!(result.is_err(), "wrong context should not verify");
}

/// Property: Ed448ph verify with wrong message fails.
#[test]
fn prop_ed448ph_wrong_message_fails() {
    let sk_seed = [0x4Cu8; 57];
    let sk_signing = oxicrypto_sig::Ed448SigningKey::from_bytes(&sk_seed).expect("ed448 sk");
    let pk_bytes = sk_signing.verifying_key_bytes();

    let msg = b"original ed448ph message";
    let wrong_msg = b"tampered ed448ph message!";

    let sig = ed448ph_sign(&sk_seed, msg, None).expect("ed448ph sign");
    let result = ed448ph_verify(&pk_bytes, wrong_msg, &sig, None);
    assert!(result.is_err(), "wrong message should not verify");
}

// ── Ed448ctx property tests ───────────────────────────────────────────────────

/// Property: Ed448ctx sign/verify succeeds.
#[test]
fn prop_ed448ctx_sign_verify_succeeds() {
    let sk_seed = [0x5Bu8; 57];
    let sk_signing = oxicrypto_sig::Ed448SigningKey::from_bytes(&sk_seed).expect("ed448 sk");
    let pk_bytes = sk_signing.verifying_key_bytes();
    let ctx = b"oxicrypto-protocol-v1";

    let msg = b"property test: ed448ctx sign/verify";
    let sig = ed448ctx_sign(&sk_seed, msg, ctx).expect("ed448ctx sign");
    ed448ctx_verify(&pk_bytes, msg, &sig, ctx).expect("ed448ctx verify");
}

/// Property: Ed448ctx verify with empty context succeeds (context="" is allowed).
#[test]
fn prop_ed448ctx_empty_context() {
    let sk_seed = [0x6Au8; 57];
    let sk_signing = oxicrypto_sig::Ed448SigningKey::from_bytes(&sk_seed).expect("ed448 sk");
    let pk_bytes = sk_signing.verifying_key_bytes();

    let msg = b"ed448ctx with empty context";
    let sig = ed448ctx_sign(&sk_seed, msg, b"").expect("ed448ctx sign");
    ed448ctx_verify(&pk_bytes, msg, &sig, b"").expect("ed448ctx verify");
}

/// Property: Ed448ctx context > 255 bytes is rejected.
#[test]
fn prop_ed448ctx_oversized_context_rejected() {
    let sk_seed = [0x7Bu8; 57];
    let long_ctx = vec![0x41u8; 256]; // 256 bytes > 255 limit
    let result = ed448ctx_sign(&sk_seed, b"msg", &long_ctx);
    assert_eq!(
        result,
        Err(CryptoError::BadInput),
        "256-byte context must be rejected"
    );
}

// ── RSA-OAEP property tests ───────────────────────────────────────────────────

/// Property: RSA-OAEP encrypt → decrypt round-trip succeeds using generated keys.
///
/// Marked `#[ignore]` because RSA key generation is slow (1–3 seconds for 2048-bit).
/// Run with `cargo test -- --include-ignored` to exercise this test.
#[test]
#[ignore = "RSA keygen is slow (1-3s for 2048-bit) — run with --include-ignored"]
fn prop_rsa_oaep_sha256_round_trip() {
    let (sk_der, pk_der) = oxicrypto_sig::rsa_sig::rsa_generate_keypair(2048).expect("rsa keygen");

    let plaintext = b"RSA-OAEP property test message (max 190 bytes for 2048-bit key)";
    let ciphertext = rsa_oaep_sha256_encrypt(&pk_der, plaintext).expect("oaep encrypt");
    let decrypted = rsa_oaep_sha256_decrypt(&sk_der, &ciphertext).expect("oaep decrypt");
    assert_eq!(
        decrypted, plaintext,
        "decrypted must match original plaintext"
    );
}

/// Property: RSA-OAEP decrypt with wrong private key fails.
///
/// Marked `#[ignore]` because RSA key generation is slow.
#[test]
#[ignore = "RSA keygen is slow (1-3s for 2048-bit) — run with --include-ignored"]
fn prop_rsa_oaep_wrong_key_fails() {
    let (sk_der, pk_der) =
        oxicrypto_sig::rsa_sig::rsa_generate_keypair(2048).expect("rsa keygen 1");
    let (wrong_sk_der, _) =
        oxicrypto_sig::rsa_sig::rsa_generate_keypair(2048).expect("rsa keygen 2");

    let plaintext = b"oaep wrong-key isolation test";
    let ciphertext = rsa_oaep_sha256_encrypt(&pk_der, plaintext).expect("oaep encrypt");
    let result = rsa_oaep_sha256_decrypt(&wrong_sk_der, &ciphertext);
    assert!(result.is_err(), "wrong private key must not decrypt");

    // Verify with correct key still works
    let decrypted = rsa_oaep_sha256_decrypt(&sk_der, &ciphertext).expect("oaep decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Property: RSA-OAEP with tampered ciphertext fails.
///
/// Marked `#[ignore]` because RSA key generation is slow.
#[test]
#[ignore = "RSA keygen is slow (1-3s for 2048-bit) — run with --include-ignored"]
fn prop_rsa_oaep_tampered_ciphertext_fails() {
    let (sk_der, pk_der) = oxicrypto_sig::rsa_sig::rsa_generate_keypair(2048).expect("rsa keygen");

    let plaintext = b"oaep tamper test";
    let mut ciphertext = rsa_oaep_sha256_encrypt(&pk_der, plaintext).expect("oaep encrypt");

    // Tamper with the last byte
    if let Some(last) = ciphertext.last_mut() {
        *last ^= 0xff;
    }

    let result = rsa_oaep_sha256_decrypt(&sk_der, &ciphertext);
    assert!(result.is_err(), "tampered ciphertext must not decrypt");
}
