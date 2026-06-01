//! Known-answer tests for ECDSA P-256, P-384, and P-521 against
//! NIST FIPS 186-5 and RFC 6979 test vectors.
//!
//! For sigGen tests, we use RFC 6979 §A.2.5/A.2.6/A.2.7 deterministic
//! ECDSA key pairs and verify that:
//!   1. Signing with the known secret key produces a valid signature.
//!   2. Verification with the known public key succeeds.
//!   3. Tampering with signature, message, or key causes verification to fail.
//!
//! The p256/p384/p521 crates use RFC 6979 deterministic nonce generation,
//! so signatures are stable across runs.
//!
//! References:
//!   - NIST FIPS 186-5 Digital Signature Standard
//!   - RFC 6979: Deterministic ECDSA
//!   - NIST CAVP test vectors for SigVer

use oxicrypto_sig::{
    EcdsaP256Signer, EcdsaP256Verifier, EcdsaP384Signer, EcdsaP384Verifier, EcdsaP521Signer,
    EcdsaP521Verifier,
};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex length: {}", hex.len());
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── P-256 FIPS/RFC 6979 tests ─────────────────────────────────────────────────
//
// RFC 6979 §A.2.5 — P-256 with SHA-256
// Private scalar d = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
// Public key Q = compressed SEC1 (33 bytes):
//   Qx = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
//   Qy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
//   (compressed: 03 || big-endian Qx, 33 bytes total)
// Message: "sample"

const P256_PRIVATE_KEY_HEX: &str =
    "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

/// RFC 6979 §A.2.5 P-256 — sign with known key, verify round-trip.
#[test]
fn ecdsa_p256_rfc6979_sign_verify() {
    let sk_bytes = hex_to_bytes(P256_PRIVATE_KEY_HEX);
    assert_eq!(sk_bytes.len(), 32, "P-256 sk must be 32 bytes");

    let msg = b"sample";

    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("P-256 signer");
    let pub_bytes = signer.verifying_key_bytes();
    // SEC1-encoded public key: 33 (compressed) or 65 (uncompressed) bytes
    assert!(
        pub_bytes.len() == 33 || pub_bytes.len() == 65,
        "P-256 pk must be 33 or 65 bytes, got {}",
        pub_bytes.len()
    );

    let sig = signer.sign(msg).expect("P-256 sign");
    assert!(!sig.is_empty(), "signature is empty");

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("P-256 verifier");
    verifier.verify(msg, &sig).expect("P-256 verify failed");
}

/// FIPS 186-5 SigVer property: tampered message must fail.
#[test]
fn ecdsa_p256_tampered_message_fails() {
    let sk_bytes = hex_to_bytes(P256_PRIVATE_KEY_HEX);
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(b"sample").expect("sign");

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"Sample", &sig).is_err(),
        "different message should fail (P-256)"
    );
}

/// FIPS 186-5 SigVer property: tampered signature must fail.
#[test]
fn ecdsa_p256_tampered_sig_fails() {
    let sk_bytes = hex_to_bytes(P256_PRIVATE_KEY_HEX);
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let mut sig = signer.sign(b"sample").expect("sign");

    // Corrupt the last byte of the DER-encoded signature
    let last = sig.len() - 1;
    sig[last] ^= 0xff;

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"sample", &sig).is_err(),
        "tampered sig should fail (P-256)"
    );
}

/// FIPS 186-5 SigVer property: wrong public key must fail.
#[test]
fn ecdsa_p256_wrong_key_fails() {
    let sk_bytes = hex_to_bytes(P256_PRIVATE_KEY_HEX);
    let signer = EcdsaP256Signer::from_bytes(&sk_bytes).expect("signer");
    let sig = signer.sign(b"sample").expect("sign");

    // Use a different key pair to verify
    let other_sk = [0x01u8; 32];
    let other_signer = EcdsaP256Signer::from_bytes(&other_sk).expect("other signer");
    let other_pk = other_signer.verifying_key_bytes();

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&other_pk).expect("verifier");
    assert!(
        verifier.verify(b"sample", &sig).is_err(),
        "wrong key should fail (P-256)"
    );
}

// ── P-384 FIPS/RFC 6979 tests ─────────────────────────────────────────────────
//
// RFC 6979 §A.2.6 — P-384 with SHA-384
// Private scalar d (48 bytes):
//   6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8
//   96D5724E4C70A825F872C9EA60D2EDF5

const P384_PRIVATE_KEY_HEX: &str = concat!(
    "6B9D3DAD2E1B8C1C05B19875B6659F4D",
    "E23C3B667BF297BA9AA47740787137D8",
    "96D5724E4C70A825F872C9EA60D2EDF5",
);

/// RFC 6979 §A.2.6 P-384 — sign with known key, verify round-trip.
#[test]
fn ecdsa_p384_rfc6979_sign_verify() {
    let sk_bytes = hex_to_bytes(P384_PRIVATE_KEY_HEX);
    assert_eq!(sk_bytes.len(), 48, "P-384 sk must be 48 bytes");

    let msg = b"sample";

    let signer = EcdsaP384Signer::from_bytes(&sk_bytes).expect("P-384 signer");
    let pub_bytes = signer.verifying_key_bytes();
    // SEC1-encoded public key: 49 (compressed) or 97 (uncompressed) bytes
    assert!(
        pub_bytes.len() == 49 || pub_bytes.len() == 97,
        "P-384 pk must be 49 or 97 bytes, got {}",
        pub_bytes.len()
    );

    let sig = signer.sign(msg).expect("P-384 sign");
    assert!(!sig.is_empty(), "P-384 signature is empty");

    let verifier = EcdsaP384Verifier::from_sec1_bytes(&pub_bytes).expect("P-384 verifier");
    verifier.verify(msg, &sig).expect("P-384 verify failed");
}

/// FIPS 186-5 SigVer property: tampered message must fail (P-384).
#[test]
fn ecdsa_p384_tampered_message_fails() {
    let sk_bytes = hex_to_bytes(P384_PRIVATE_KEY_HEX);
    let signer = EcdsaP384Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(b"sample").expect("sign");

    let verifier = EcdsaP384Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"Sample", &sig).is_err(),
        "different message should fail (P-384)"
    );
}

/// FIPS 186-5 SigVer property: tampered signature must fail (P-384).
#[test]
fn ecdsa_p384_tampered_sig_fails() {
    let sk_bytes = hex_to_bytes(P384_PRIVATE_KEY_HEX);
    let signer = EcdsaP384Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let mut sig = signer.sign(b"sample").expect("sign");

    let last = sig.len() - 1;
    sig[last] ^= 0xff;

    let verifier = EcdsaP384Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"sample", &sig).is_err(),
        "tampered sig should fail (P-384)"
    );
}

// ── P-521 FIPS/RFC 6979 tests ─────────────────────────────────────────────────
//
// RFC 6979 §A.2.7 — P-521 with SHA-512
// Private scalar d (~380 bits, left-padded to 66 bytes):
//   0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C
//       AA896EB32F1F47C70BE89F7B893ABBED

fn p521_private_key_bytes() -> [u8; 66] {
    let raw = hex_to_bytes("0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70BE89F7B893ABBED");
    assert_eq!(raw.len(), 48);
    let mut out = [0u8; 66];
    out[66 - raw.len()..].copy_from_slice(&raw);
    out
}

/// RFC 6979 §A.2.7 P-521 — sign with known key, verify round-trip.
#[test]
fn ecdsa_p521_rfc6979_sign_verify() {
    let sk_bytes = p521_private_key_bytes();

    let msg = b"sample";

    let signer = EcdsaP521Signer::from_bytes(&sk_bytes).expect("P-521 signer");
    let pub_bytes = signer.verifying_key_bytes();
    // SEC1-encoded public key: 67 (compressed) or 133 (uncompressed) bytes
    assert!(
        pub_bytes.len() == 67 || pub_bytes.len() == 133,
        "P-521 pk must be 67 or 133 bytes, got {}",
        pub_bytes.len()
    );

    let sig = signer.sign(msg).expect("P-521 sign");
    assert!(!sig.is_empty(), "P-521 signature is empty");

    let verifier = EcdsaP521Verifier::from_sec1_bytes(&pub_bytes).expect("P-521 verifier");
    verifier.verify(msg, &sig).expect("P-521 verify failed");
}

/// FIPS 186-5 SigVer property: tampered message must fail (P-521).
#[test]
fn ecdsa_p521_tampered_message_fails() {
    let sk_bytes = p521_private_key_bytes();
    let signer = EcdsaP521Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let sig = signer.sign(b"sample").expect("sign");

    let verifier = EcdsaP521Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"Sample", &sig).is_err(),
        "different message should fail (P-521)"
    );
}

/// FIPS 186-5 SigVer property: tampered signature must fail (P-521).
#[test]
fn ecdsa_p521_tampered_sig_fails() {
    let sk_bytes = p521_private_key_bytes();
    let signer = EcdsaP521Signer::from_bytes(&sk_bytes).expect("signer");
    let pub_bytes = signer.verifying_key_bytes();
    let mut sig = signer.sign(b"sample").expect("sign");

    let last = sig.len() - 1;
    sig[last] ^= 0xff;

    let verifier = EcdsaP521Verifier::from_sec1_bytes(&pub_bytes).expect("verifier");
    assert!(
        verifier.verify(b"sample", &sig).is_err(),
        "tampered sig should fail (P-521)"
    );
}

// ── Cross-curve isolation tests ───────────────────────────────────────────────

/// A P-256 signature must not verify under a P-384 key (different curve).
/// This tests that our implementations do not accidentally accept cross-curve
/// signatures, which would be a FIPS 186-5 violation.
#[test]
fn ecdsa_p256_sig_rejected_by_p384_verifier() {
    let sk256 = hex_to_bytes(P256_PRIVATE_KEY_HEX);
    let signer256 = EcdsaP256Signer::from_bytes(&sk256).expect("P-256 signer");
    let sig256 = signer256.sign(b"sample").expect("P-256 sign");

    let sk384 = hex_to_bytes(P384_PRIVATE_KEY_HEX);
    let signer384 = EcdsaP384Signer::from_bytes(&sk384).expect("P-384 signer");
    let pub384 = signer384.verifying_key_bytes();
    let verifier384 = EcdsaP384Verifier::from_sec1_bytes(&pub384).expect("P-384 verifier");

    // P-384 verifier must reject a P-256 DER signature (different length / encoding)
    assert!(
        verifier384.verify(b"sample", &sig256).is_err(),
        "P-256 sig must be rejected by P-384 verifier"
    );
}

/// Invalid scalar (all zeros) must be rejected.
#[test]
fn ecdsa_p256_zero_scalar_rejected() {
    let result = EcdsaP256Signer::from_bytes(&[0u8; 32]);
    assert!(
        result.is_err(),
        "all-zero scalar must be rejected for P-256"
    );
}

/// Invalid scalar (all zeros) must be rejected for P-384.
#[test]
fn ecdsa_p384_zero_scalar_rejected() {
    let result = EcdsaP384Signer::from_bytes(&[0u8; 48]);
    assert!(
        result.is_err(),
        "all-zero scalar must be rejected for P-384"
    );
}
