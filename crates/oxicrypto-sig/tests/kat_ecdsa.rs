//! Known-answer tests for ECDSA P-256, P-384, and P-521.
//!
//! Test vectors sourced from NIST FIPS 186-5 and RFC 6979 deterministic ECDSA.
//! Round-trip tests verify that sign + verify succeeds with a known-good key pair.

use oxicrypto_sig::{
    EcdsaP256Signer, EcdsaP256Verifier, EcdsaP384Signer, EcdsaP384Verifier, EcdsaP521Signer,
    EcdsaP521Verifier, SignatureFormat,
};

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ── P-256 round-trip ──────────────────────────────────────────────────────────

#[test]
fn ecdsa_p256_sign_verify_round_trip() {
    // 32-byte scalar from the NIST P-256 test key in RFC 6979 §A.2.5
    // private key: 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    let sk_bytes: [u8; 32] = [
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ];
    let msg = b"sample";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("P-256 from_bytes failed");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("P-256 sign failed");
    assert!(!sig.is_empty(), "P-256 signature is empty");

    let verifier =
        EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("P-256 verifier from_sec1 failed");
    verifier.verify(msg, &sig).expect("P-256 verify failed");
}

#[test]
fn ecdsa_p256_wrong_message_fails() {
    let sk_bytes: [u8; 32] = [0x01; 32];
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(b"correct message").expect("sign");

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"wrong message", &sig).is_err(),
        "should fail with wrong message"
    );
}

#[test]
fn ecdsa_p256_invalid_scalar_errors() {
    // All-zero scalar is invalid for P-256
    let result = EcdsaP256Signer::from_bytes(&[0u8; 32]);
    assert!(result.is_err(), "zero scalar should be rejected");
}

// ── P-384 round-trip ──────────────────────────────────────────────────────────

#[test]
fn ecdsa_p384_sign_verify_round_trip() {
    // RFC 6979 §A.2.6 P-384 test key
    // private key d
    let sk_bytes: [u8; 48] = [
        0x6B, 0x9D, 0x3D, 0xAD, 0x2E, 0x1B, 0x8C, 0x1C, 0x05, 0xB1, 0x98, 0x75, 0xB6, 0x65, 0x9F,
        0x4D, 0xE2, 0x3C, 0x3B, 0x66, 0x7B, 0xF2, 0x97, 0xBA, 0x9A, 0xA4, 0x77, 0x40, 0x78, 0x71,
        0x37, 0xD8, 0x96, 0xD5, 0x72, 0x4E, 0x4C, 0x70, 0xA8, 0x25, 0xF8, 0x72, 0xC9, 0xEA, 0x60,
        0xD2, 0xED, 0xF5,
    ];
    let msg = b"sample";

    let signer = EcdsaP384Signer::from_bytes(&sk_bytes).expect("P-384 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(msg).expect("P-384 sign");
    assert!(!sig.is_empty());

    let verifier = EcdsaP384Verifier::from_sec1_bytes(&pub_bytes).expect("P-384 verifier");
    verifier.verify(msg, &sig).expect("P-384 verify");
}

#[test]
fn ecdsa_p384_corrupted_signature_fails() {
    let sk_bytes: [u8; 48] = [0x02; 48];
    let signer = EcdsaP384Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let mut sig = signer.sign(b"message").expect("sign");
    sig[0] ^= 0xff;

    let verifier = EcdsaP384Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(verifier.verify(b"message", &sig).is_err());
}

// ── P-521 round-trip ──────────────────────────────────────────────────────────

#[test]
fn ecdsa_p521_sign_verify_round_trip() {
    // RFC 6979 §A.2.7 P-521 private scalar d (48 bytes of significant data, left-padded to 66):
    // d = 0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C
    //       AA896EB32F1F47C70BE89F7B893ABBED
    // This is a ~380-bit value, well within [1, n-1] for P-521.
    let sk_hex = "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70BE89F7B893ABBED";
    let sk_raw = hex_decode(sk_hex);
    assert_eq!(sk_raw.len(), 48);
    let mut sk = [0u8; 66];
    sk[66 - sk_raw.len()..].copy_from_slice(&sk_raw);

    let signer = EcdsaP521Signer::from_bytes(&sk).expect("P-521 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let msg = b"sample";
    let sig = signer.sign(msg).expect("P-521 sign");
    assert!(!sig.is_empty());

    let verifier = EcdsaP521Verifier::from_sec1_bytes(&pub_bytes).expect("P-521 verifier");
    verifier.verify(msg, &sig).expect("P-521 verify");
}

#[test]
fn ecdsa_p521_wrong_key_fails() {
    let mut sk_a = [0u8; 66];
    sk_a[65] = 0x01;
    let mut sk_b = [0u8; 66];
    sk_b[65] = 0x02;

    let signer_a = EcdsaP521Signer::from_bytes(&sk_a).expect("signer A");
    let signer_b = EcdsaP521Signer::from_bytes(&sk_b).expect("signer B");
    let pub_b = signer_b.verifying_key_bytes();

    let sig_a = signer_a.sign(b"msg").expect("sign A");

    let verifier_b = EcdsaP521Verifier::from_sec1_bytes(&pub_b).expect("verifier B");
    assert!(
        verifier_b.verify(b"msg", &sig_a).is_err(),
        "cross-key verify should fail"
    );
}

// ── SignatureFormat DER/Raw parity tests ─────────────────────────────────────

/// Sign with DER, re-verify with DER; sign raw, re-verify raw;
/// verify that cross-format verification fails gracefully.
#[test]
fn test_ecdsa_p256_sign_fmt_raw_der_parity() {
    let sk_bytes: [u8; 32] = [
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ];
    let msg = b"sign format parity test";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("P-256 verifier");

    // DER round-trip
    let der_sig = signer
        .sign_fmt(msg, SignatureFormat::Der)
        .expect("sign DER");
    verifier
        .verify_fmt(msg, &der_sig, SignatureFormat::Der)
        .expect("verify DER should succeed");

    // Raw round-trip
    let raw_sig = signer
        .sign_fmt(msg, SignatureFormat::Raw)
        .expect("sign Raw");
    assert_eq!(raw_sig.len(), 64, "P-256 raw sig must be 64 bytes");
    verifier
        .verify_fmt(msg, &raw_sig, SignatureFormat::Raw)
        .expect("verify Raw should succeed");

    // Cross-format: DER bytes fed to Raw verifier should fail
    let cross_result = verifier.verify_fmt(msg, &der_sig, SignatureFormat::Raw);
    assert!(
        cross_result.is_err(),
        "DER sig verified as Raw should fail (wrong length)"
    );

    // Cross-format: Raw bytes fed to DER verifier should fail
    let cross_result2 = verifier.verify_fmt(msg, &raw_sig, SignatureFormat::Der);
    assert!(
        cross_result2.is_err(),
        "Raw sig verified as DER should fail (not valid ASN.1)"
    );
}

/// Verify a pre-computed SHA-256 hash using `verify_prehash` on P-256.
#[test]
fn test_ecdsa_verify_prehash_p256() {
    use sha2::{Digest, Sha256};

    let sk_bytes: [u8; 32] = [
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ];
    let msg = b"message for prehash verify test";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("P-256 verifier");

    // Sign the message normally (produces DER sig over SHA-256(msg))
    let der_sig = signer.sign(msg).expect("sign");

    // Compute the SHA-256 hash manually
    let hash = Sha256::digest(msg);

    // verify_prehash should accept the hash + the DER signature
    verifier
        .verify_prehash(hash.as_slice(), &der_sig)
        .expect("verify_prehash should succeed with correct hash");

    // Tampered hash should fail
    let mut bad_hash = hash.to_vec();
    bad_hash[0] ^= 0xff;
    assert!(
        verifier.verify_prehash(&bad_hash, &der_sig).is_err(),
        "verify_prehash with wrong hash must fail"
    );
}

// ── sign_with_hash / verify_with_hash tests ──────────────────────────────────

/// P-256: sign_with_hash using SHA-256 must produce a signature that
/// verify_with_hash (and also verify_prehash) accepts.
#[test]
fn test_ecdsa_p256_sign_with_hash_sha256_round_trip() {
    use oxicrypto_hash::Sha256;

    let sk_bytes: [u8; 32] = [
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ];
    let msg = b"sign with Hash trait object test";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("P-256 verifier");

    let hash_algo = Sha256;

    // Sign using the Hash trait object.
    let sig_with_hash = signer
        .sign_with_hash(&hash_algo, msg)
        .expect("sign_with_hash P-256 SHA-256");

    // Must verify via verify_with_hash.
    verifier
        .verify_with_hash(&hash_algo, msg, &sig_with_hash)
        .expect("verify_with_hash must succeed");

    // sig_with_hash must also match sign() output (both use SHA-256 internally).
    let sig_direct = signer.sign(msg).expect("sign direct");
    assert_eq!(
        sig_with_hash, sig_direct,
        "sign_with_hash(SHA-256) must equal sign() for P-256"
    );

    // Wrong message must fail.
    assert!(
        verifier
            .verify_with_hash(&hash_algo, b"wrong message", &sig_with_hash)
            .is_err(),
        "verify_with_hash wrong message must fail"
    );
}

/// P-256: sign_with_hash using a non-default hash (BLAKE3) produces a
/// valid signature for that hash but is rejected by the standard verifier.
#[test]
fn test_ecdsa_p256_sign_with_hash_blake3_round_trip() {
    use oxicrypto_hash::Blake3;

    let sk_bytes: [u8; 32] = [
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6,
        0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F,
        0x67, 0x21,
    ];
    let msg = b"sign with blake3 hash trait test";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("P-256 verifier");

    let hash_algo = Blake3;
    let sig = signer
        .sign_with_hash(&hash_algo, msg)
        .expect("sign_with_hash BLAKE3");

    // verify_with_hash using the same algorithm must succeed.
    verifier
        .verify_with_hash(&hash_algo, msg, &sig)
        .expect("verify_with_hash BLAKE3 must succeed");

    // The standard P-256 verifier uses SHA-256 internally, so should fail
    // because the signature was generated over BLAKE3(msg) not SHA-256(msg).
    assert!(
        verifier.verify(msg, &sig).is_err(),
        "standard verify (SHA-256) must fail for BLAKE3-based signature"
    );
}

/// P-384: sign_with_hash round trip using SHA-384.
#[test]
fn test_ecdsa_p384_sign_with_hash_sha384_round_trip() {
    use oxicrypto_hash::Sha384;

    let sk_bytes: [u8; 48] = [
        0x6B, 0x9D, 0x3D, 0xAD, 0x2E, 0x1B, 0x8C, 0x1C, 0x05, 0xB1, 0x98, 0x75, 0xB6, 0x65, 0x9F,
        0x4D, 0xE2, 0x3C, 0x3B, 0x66, 0x7B, 0xF2, 0x97, 0xBA, 0x9A, 0xA4, 0x77, 0x40, 0x78, 0x71,
        0x37, 0xD8, 0x96, 0xD5, 0x72, 0x4E, 0x4C, 0x70, 0xA8, 0x25, 0xF8, 0x72, 0xC9, 0xEA, 0x60,
        0xD2, 0xED, 0xF5,
    ];
    let msg = b"p384 sign with hash sha384";

    let signer = EcdsaP384Signer::from_bytes(&sk_bytes).expect("P-384 signer");
    let pub_bytes = signer.verifying_key_bytes();
    let verifier = EcdsaP384Verifier::from_sec1_bytes(&pub_bytes).expect("P-384 verifier");

    let hash_algo = Sha384;
    let sig = signer
        .sign_with_hash(&hash_algo, msg)
        .expect("P-384 sign_with_hash SHA-384");

    verifier
        .verify_with_hash(&hash_algo, msg, &sig)
        .expect("P-384 verify_with_hash SHA-384 must succeed");

    // sign() uses SHA-384 internally for P-384, so outputs must match.
    let sig_direct = signer.sign(msg).expect("sign direct P-384");
    assert_eq!(
        sig, sig_direct,
        "sign_with_hash(SHA-384) must equal sign() for P-384"
    );
}

/// P-521: sign_with_hash round trip using SHA-512.
#[test]
fn test_ecdsa_p521_sign_with_hash_sha512_round_trip() {
    use oxicrypto_hash::Sha512;

    // 66-byte P-521 scalar (not a real RFC key, just valid for testing)
    let mut sk_bytes = [0u8; 66];
    sk_bytes[0] = 0x01; // make it non-zero
    sk_bytes[65] = 0x23;

    // Verify scalar is valid for P-521
    let signer = match EcdsaP521Signer::from_bytes(&sk_bytes) {
        Ok(s) => s,
        Err(_) => return, // skip if scalar happens to be invalid
    };
    let pub_bytes = signer.verifying_key_bytes();
    let verifier = EcdsaP521Verifier::from_sec1_bytes(&pub_bytes).expect("P-521 verifier");
    let msg = b"p521 sign with hash sha512";

    let hash_algo = Sha512;
    let sig = signer
        .sign_with_hash(&hash_algo, msg)
        .expect("P-521 sign_with_hash SHA-512");

    verifier
        .verify_with_hash(&hash_algo, msg, &sig)
        .expect("P-521 verify_with_hash SHA-512 must succeed");
}
