//! Fuzz tests for oxicrypto-sig.
//!
//! These tests verify that `verify()` and `from_*` constructors never panic
//! for arbitrary (malformed, random) public keys, messages, and signatures.
//! Every call must return either `Ok` or a typed `Err`, never an unwinding panic.

use oxicrypto_core::Verifier;
use oxicrypto_sig::{EcdsaP256Verifier, EcdsaP384Verifier, EcdsaP521Verifier};

// ── LCG helper for deterministic pseudo-random test bytes ────────────────────

/// Simple linear-congruential generator for deterministic, low-overhead test
/// byte sequence generation.  NOT cryptographically secure — test-only.
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

// ── Ed25519 ───────────────────────────────────────────────────────────────────

/// Ed25519 `verify` must never panic on arbitrary public keys / signatures.
/// Uses the `ed25519_dalek` API directly (the same path as OxiCrypto's internal impl).
#[test]
fn fuzz_ed25519_verify_never_panics() {
    use ed25519_dalek::Verifier as DalekVerifier;
    use ed25519_dalek::{Signature, VerifyingKey};

    let msg = b"fuzz_test_message";

    // Iterate over many pseudo-random (pk, sig) pairs.
    for i in 0u64..500 {
        let pk_bytes: [u8; 32] = lcg_bytes(i.wrapping_mul(7919), 32)
            .try_into()
            .expect("32 bytes");
        let sig_bytes: [u8; 64] = lcg_bytes(i.wrapping_mul(7883), 64)
            .try_into()
            .expect("64 bytes");
        // VerifyingKey::from_bytes and Signature::from_bytes may return errors
        // for invalid points — must not panic.
        if let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) {
            let sig = Signature::from_bytes(&sig_bytes);
            let _ = vk.verify(msg, &sig);
        }
    }

    // Wrong-length public keys must not panic (handled at the try_into stage).
    for bad_pk_len in [0usize, 1, 16, 31, 33, 64] {
        let pk = lcg_bytes(0xABCD + bad_pk_len as u64, bad_pk_len);
        // Attempt conversion — if it fails (wrong length), that is fine.
        if let Ok(pk_arr) = <[u8; 32]>::try_from(pk.as_slice()) {
            let _ = VerifyingKey::from_bytes(&pk_arr);
        }
    }
}

// ── ECDSA P-256 ───────────────────────────────────────────────────────────────

/// ECDSA P-256 `verify` must never panic on arbitrary public keys / signatures.
#[test]
fn fuzz_ecdsa_p256_verify_never_panics() {
    let msg = b"fuzz_test_message_p256";

    // First, obtain a valid verifying key for construction tests.
    // We know a valid P-256 scalar from KAT vectors.
    let valid_scalar = &[
        0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xd2, 0x61, 0x2e, 0x37, 0xbd, 0x22, 0x6d, 0x4e,
        0x13, 0xa7, 0xb4, 0x62, 0x36, 0x68, 0xdc, 0xa7, 0x03, 0x4e, 0x98, 0x17, 0x76, 0x4a, 0x67,
        0x62, 0x57,
    ];
    let signer =
        oxicrypto_sig::EcdsaP256Signer::from_bytes(valid_scalar).expect("valid P-256 signer");
    let valid_pk = signer.verifying_key_bytes();
    let verifier = EcdsaP256Verifier::from_sec1_bytes(&valid_pk).expect("valid P-256 verifier");

    // Fuzz verify() with valid pk + random signatures.
    for i in 0u64..500 {
        // DER-encoded signatures of various lengths.
        for sig_len in [0usize, 1, 32, 64, 72, 128] {
            let sig = lcg_bytes(i.wrapping_add(sig_len as u64 * 1000), sig_len);
            let _ = verifier.verify(msg, &sig);
        }
    }

    // Fuzz with arbitrary pk + random sig.
    for i in 0u64..200 {
        for pk_len in [0usize, 1, 33, 65, 128] {
            let pk = lcg_bytes(i.wrapping_mul(31) + pk_len as u64, pk_len);
            let sig = lcg_bytes(i.wrapping_mul(37) + pk_len as u64 + 1000, 72);
            if let Ok(v) = EcdsaP256Verifier::from_sec1_bytes(&pk) {
                let _ = v.verify(msg, &sig);
            }
        }
    }
}

/// ECDSA P-256 `from_sec1_bytes` must never panic on arbitrary-length input.
#[test]
fn fuzz_ecdsa_p256_from_sec1_bytes_never_panics() {
    for i in 0u64..256 {
        for len in [0usize, 1, 32, 33, 64, 65, 66, 97, 128] {
            let bytes = lcg_bytes(i * 1000 + len as u64, len);
            let _ = EcdsaP256Verifier::from_sec1_bytes(&bytes);
        }
    }
}

// ── ECDSA P-384 ───────────────────────────────────────────────────────────────

/// ECDSA P-384 `from_sec1_bytes` and `verify` must never panic.
#[test]
fn fuzz_ecdsa_p384_verify_never_panics() {
    let msg = b"fuzz_test_message_p384";

    for i in 0u64..128 {
        for len in [0usize, 1, 48, 49, 97, 128] {
            let bytes = lcg_bytes(i * 2000 + len as u64, len);
            // Constructor must not panic.
            if let Ok(verifier) = EcdsaP384Verifier::from_sec1_bytes(&bytes) {
                // Verify with random signature must not panic.
                for sig_len in [0usize, 64, 96, 128] {
                    let sig = lcg_bytes(i.wrapping_add(sig_len as u64 * 500), sig_len);
                    let _ = verifier.verify(msg, &sig);
                }
            }
        }
    }
}

// ── ECDSA P-521 ───────────────────────────────────────────────────────────────

/// ECDSA P-521 `from_sec1_bytes` and `verify` must never panic.
#[test]
fn fuzz_ecdsa_p521_verify_never_panics() {
    let msg = b"fuzz_test_message_p521";

    for i in 0u64..64 {
        for len in [0usize, 1, 65, 66, 67, 133, 200] {
            let bytes = lcg_bytes(i * 3000 + len as u64, len);
            if let Ok(verifier) = EcdsaP521Verifier::from_sec1_bytes(&bytes) {
                for sig_len in [0usize, 64, 96, 132, 200] {
                    let sig = lcg_bytes(i.wrapping_add(sig_len as u64 * 300), sig_len);
                    let _ = verifier.verify(msg, &sig);
                }
            }
        }
    }
}

// ── RSA ───────────────────────────────────────────────────────────────────────

/// RSA PKCS#1v15 `from_spki_der` and `verify` must never panic on arbitrary input.
#[test]
fn fuzz_rsa_pkcs1_verify_never_panics() {
    use oxicrypto_sig::rsa_sig::RsaPkcs1v15Sha256Verifier;

    // Try constructing from arbitrary DER bytes — must not panic.
    for i in 0u64..64 {
        for len in [0usize, 1, 16, 32, 100, 256, 512] {
            let der = lcg_bytes(i * 4000 + len as u64, len);
            // Constructor must return Ok or Err — never panic (try both SPKI and PKCS1 DER).
            if let Ok(verifier) = RsaPkcs1v15Sha256Verifier::from_spki_der(&der) {
                // verify() with random sig must not panic.
                for sig_len in [0usize, 32, 64, 256, 512] {
                    let sig = lcg_bytes(i + sig_len as u64, sig_len);
                    let _ = verifier.verify(b"test message", &sig);
                }
            }
            if let Ok(verifier) = RsaPkcs1v15Sha256Verifier::from_pkcs1_der(&der) {
                for sig_len in [0usize, 32, 64, 256, 512] {
                    let sig = lcg_bytes(i + sig_len as u64 + 10000, sig_len);
                    let _ = verifier.verify(b"test message 2", &sig);
                }
            }
        }
    }
}

// ── SchnorrBip340 ─────────────────────────────────────────────────────────────

/// SchnorrBip340 `parse_public_key` and `verify` must never panic on arbitrary bytes.
#[test]
fn fuzz_schnorr_bip340_verify_never_panics() {
    use oxicrypto_sig::SchnorrBip340;

    let schnorr = SchnorrBip340;

    // Test with Verifier trait: all arbitrary pk + msg + sig.
    for i in 0u64..200 {
        for pk_len in [0usize, 1, 32, 33, 64] {
            let pk = lcg_bytes(i * 5000 + pk_len as u64, pk_len);
            let msg = lcg_bytes(i * 5001 + pk_len as u64, 32);
            let sig = lcg_bytes(i * 5002 + pk_len as u64, 64);
            // Must return Ok or Err — never panic.
            let _ = schnorr.verify(&pk, &msg, &sig);
        }
    }

    // Also test `parse_public_key` with garbage bytes.
    for i in 0u64..256 {
        let bytes = lcg_bytes(i * 6000, 32);
        let _ = SchnorrBip340::parse_public_key(&bytes);
    }
    // Wrong lengths.
    for bad_len in [0usize, 1, 16, 31, 33, 64] {
        let bytes = lcg_bytes(bad_len as u64, bad_len);
        let _ = SchnorrBip340::parse_public_key(&bytes);
    }
}
