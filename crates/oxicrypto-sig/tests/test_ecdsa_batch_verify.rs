//! Batch verification tests for ECDSA P-256 and P-384.
//!
//! Note: ECDSA does not support true batching (unlike EdDSA). These tests
//! verify the sequential-loop batch API behaves correctly.

use oxicrypto_sig::{
    ecdsa_p256_verify_batch, ecdsa_p384_verify_batch, EcdsaP256Signer, EcdsaP256Verifier,
    EcdsaP384Signer, EcdsaP384Verifier,
};

/// Generate a P-256 signer + verifier + a DER signature over `msg`.
fn p256_keypair_and_sign(scalar: u8, msg: &[u8]) -> (EcdsaP256Verifier, Vec<u8>) {
    let mut sk = [0u8; 32];
    sk[31] = scalar;
    let signer = EcdsaP256Signer::from_bytes(&sk).expect("P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("P-256 sign");
    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("P-256 verifier");
    (verifier, sig)
}

/// Generate a P-384 signer + verifier + a DER signature over `msg`.
fn p384_keypair_and_sign(scalar: u8, msg: &[u8]) -> (EcdsaP384Verifier, Vec<u8>) {
    let mut sk = [0u8; 48];
    sk[47] = scalar;
    let signer = EcdsaP384Signer::from_bytes(&sk).expect("P-384 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("P-384 sign");
    let verifier = EcdsaP384Verifier::from_sec1_bytes(&pub_bytes).expect("P-384 verifier");
    (verifier, sig)
}

// ── P-256 batch tests ─────────────────────────────────────────────────────────

/// Five valid P-256 key-pairs with distinct messages: batch verify succeeds.
#[test]
fn ecdsa_p256_batch_pass() {
    let msgs: [&[u8]; 5] = [b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"];
    let scalars: [u8; 5] = [1, 2, 3, 4, 5];

    let mut verifiers = Vec::new();
    let mut sigs_owned = Vec::new();
    for (i, msg) in msgs.iter().enumerate() {
        let (vk, sig) = p256_keypair_and_sign(scalars[i], msg);
        verifiers.push(vk);
        sigs_owned.push(sig);
    }

    let sig_refs: Vec<&[u8]> = sigs_owned.iter().map(|s| s.as_slice()).collect();
    let msg_refs: Vec<&[u8]> = msgs.to_vec();

    ecdsa_p256_verify_batch(&verifiers, &msg_refs, &sig_refs)
        .expect("batch verify of 5 valid P-256 sigs should succeed");
}

/// Tamper one P-256 signature in a batch of 5; batch verify returns error.
#[test]
fn ecdsa_p256_batch_tamper() {
    let msgs: [&[u8]; 5] = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"];
    let scalars: [u8; 5] = [6, 7, 8, 9, 10];

    let mut verifiers = Vec::new();
    let mut sigs_owned = Vec::new();
    for (i, msg) in msgs.iter().enumerate() {
        let (vk, sig) = p256_keypair_and_sign(scalars[i], msg);
        verifiers.push(vk);
        sigs_owned.push(sig);
    }

    // Tamper the third signature
    sigs_owned[2][0] ^= 0xff;

    let sig_refs: Vec<&[u8]> = sigs_owned.iter().map(|s| s.as_slice()).collect();
    let msg_refs: Vec<&[u8]> = msgs.to_vec();

    let result = ecdsa_p256_verify_batch(&verifiers, &msg_refs, &sig_refs);
    assert!(
        result.is_err(),
        "batch verify with one tampered P-256 sig should fail"
    );
}

/// Empty P-256 batch succeeds.
#[test]
fn ecdsa_p256_batch_empty() {
    let result = ecdsa_p256_verify_batch(&[], &[], &[]);
    assert!(result.is_ok(), "empty P-256 batch should succeed");
}

/// Mismatched slice lengths return BadInput.
#[test]
fn ecdsa_p256_batch_mismatched_lengths() {
    use oxicrypto_core::CryptoError;

    let (vk, sig) = p256_keypair_and_sign(1, b"test");
    let result = ecdsa_p256_verify_batch(&[vk], &[b"test", b"extra"], &[sig.as_slice()]);
    assert_eq!(
        result,
        Err(CryptoError::BadInput),
        "mismatched slice lengths should return BadInput"
    );
}

// ── P-384 batch tests ─────────────────────────────────────────────────────────

/// Five valid P-384 key-pairs with distinct messages: batch verify succeeds.
#[test]
fn ecdsa_p384_batch_pass() {
    let msgs: [&[u8]; 5] = [b"384msg1", b"384msg2", b"384msg3", b"384msg4", b"384msg5"];
    let scalars: [u8; 5] = [1, 2, 3, 4, 5];

    let mut verifiers = Vec::new();
    let mut sigs_owned = Vec::new();
    for (i, msg) in msgs.iter().enumerate() {
        let (vk, sig) = p384_keypair_and_sign(scalars[i], msg);
        verifiers.push(vk);
        sigs_owned.push(sig);
    }

    let sig_refs: Vec<&[u8]> = sigs_owned.iter().map(|s| s.as_slice()).collect();
    let msg_refs: Vec<&[u8]> = msgs.to_vec();

    ecdsa_p384_verify_batch(&verifiers, &msg_refs, &sig_refs)
        .expect("batch verify of 5 valid P-384 sigs should succeed");
}

/// Tamper one P-384 signature in a batch of 5; batch verify returns error.
#[test]
fn ecdsa_p384_batch_tamper() {
    let msgs: [&[u8]; 5] = [b"a384", b"b384", b"c384", b"d384", b"e384"];
    let scalars: [u8; 5] = [11, 12, 13, 14, 15];

    let mut verifiers = Vec::new();
    let mut sigs_owned = Vec::new();
    for (i, msg) in msgs.iter().enumerate() {
        let (vk, sig) = p384_keypair_and_sign(scalars[i], msg);
        verifiers.push(vk);
        sigs_owned.push(sig);
    }

    // Tamper the first signature
    sigs_owned[0][0] ^= 0xff;

    let sig_refs: Vec<&[u8]> = sigs_owned.iter().map(|s| s.as_slice()).collect();
    let msg_refs: Vec<&[u8]> = msgs.to_vec();

    let result = ecdsa_p384_verify_batch(&verifiers, &msg_refs, &sig_refs);
    assert!(
        result.is_err(),
        "batch verify with one tampered P-384 sig should fail"
    );
}
