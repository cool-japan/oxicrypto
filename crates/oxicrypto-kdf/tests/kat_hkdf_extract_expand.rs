//! RFC 5869 extract+expand decomposition tests for HKDF-SHA-256.
//!
//! The combined `Kdf::derive` is already exercised by `kat_hkdf.rs`.
//! These tests exercise the separated phases (`hkdf_sha256_extract` /
//! `hkdf_sha256_expand`) against the PRK and OKM values from RFC 5869
//! Appendix A, and verify that `hkdf_sha256_derive_to_vec` produces the same
//! output as the split call sequence.

use oxicrypto_kdf::{
    hkdf_sha256_derive_to_vec, hkdf_sha256_expand, hkdf_sha256_extract, hkdf_sha384_derive_to_vec,
    hkdf_sha512_derive_to_vec,
};

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── RFC 5869 Test Case 1 — extract+expand phases separately ─────────────────

/// RFC 5869 Appendix A TC1: verify that `hkdf_sha256_extract` produces the
/// published PRK and that `hkdf_sha256_expand` then matches the published OKM.
#[test]
fn hkdf_sha256_tc1_extract_prk() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

    let prk = hkdf_sha256_extract(&salt, &ikm);
    assert_eq!(to_hex(&prk), expected_prk, "RFC 5869 TC1 PRK mismatch");
}

#[test]
fn hkdf_sha256_tc1_expand_okm() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = concat!(
        "3cb25f25faacd57a90434f64d0362f2a",
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "34007208d5b887185865",
    );

    let prk = hkdf_sha256_extract(&salt, &ikm);
    let mut okm = vec![0u8; 42];
    hkdf_sha256_expand(&prk, &info, &mut okm).expect("expand failed");
    assert_eq!(to_hex(&okm), expected_okm, "RFC 5869 TC1 OKM mismatch");
}

// ── RFC 5869 Test Case 3 — no salt, no info ──────────────────────────────────

/// RFC 5869 TC3: empty salt causes HMAC to use a zero-filled key of HashLen
/// bytes.  Verify both PRK and OKM from the RFC.
#[test]
fn hkdf_sha256_tc3_no_salt_extract_prk() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let expected_prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";

    // Empty salt
    let prk = hkdf_sha256_extract(&[], &ikm);
    assert_eq!(to_hex(&prk), expected_prk, "RFC 5869 TC3 PRK mismatch");
}

#[test]
fn hkdf_sha256_tc3_no_salt_no_info_okm() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let expected_okm = concat!(
        "8da4e775a563c18f715f802a063c5a31",
        "b8a11f5c5ee1879ec3454e5f3c738d2d",
        "9d201395faa4b61a96c8",
    );

    let prk = hkdf_sha256_extract(&[], &ikm);
    let mut okm = vec![0u8; 42];
    hkdf_sha256_expand(&prk, &[], &mut okm).expect("expand failed");
    assert_eq!(to_hex(&okm), expected_okm, "RFC 5869 TC3 OKM mismatch");
}

// ── derive_to_vec round-trips ─────────────────────────────────────────────────

/// `hkdf_sha256_derive_to_vec` must produce the same OKM as the split call.
#[test]
fn hkdf_sha256_derive_to_vec_matches_extract_expand() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");

    // Split.
    let prk = hkdf_sha256_extract(&salt, &ikm);
    let mut okm_split = vec![0u8; 42];
    hkdf_sha256_expand(&prk, &info, &mut okm_split).expect("expand failed");

    // Combined.
    let okm_vec = hkdf_sha256_derive_to_vec(&ikm, &salt, &info, 42).expect("derive_to_vec failed");

    assert_eq!(
        okm_split, okm_vec,
        "derive_to_vec must match extract+expand"
    );
}

#[test]
fn hkdf_sha256_derive_to_vec_tc3_no_salt_no_info() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let expected_okm = concat!(
        "8da4e775a563c18f715f802a063c5a31",
        "b8a11f5c5ee1879ec3454e5f3c738d2d",
        "9d201395faa4b61a96c8",
    );

    let okm = hkdf_sha256_derive_to_vec(&ikm, &[], &[], 42).expect("derive_to_vec failed");
    assert_eq!(to_hex(&okm), expected_okm);
}

/// `hkdf_sha384_derive_to_vec` must return correct length and be deterministic.
#[test]
fn hkdf_sha384_derive_to_vec_deterministic() {
    let okm1 = hkdf_sha384_derive_to_vec(b"ikm", b"salt", b"info", 48).unwrap();
    let okm2 = hkdf_sha384_derive_to_vec(b"ikm", b"salt", b"info", 48).unwrap();
    assert_eq!(okm1, okm2);
    assert_eq!(okm1.len(), 48);
    assert_ne!(okm1, vec![0u8; 48]);
}

/// `hkdf_sha512_derive_to_vec` must return correct length and be deterministic.
#[test]
fn hkdf_sha512_derive_to_vec_deterministic() {
    let okm1 = hkdf_sha512_derive_to_vec(b"ikm", b"salt", b"info", 64).unwrap();
    let okm2 = hkdf_sha512_derive_to_vec(b"ikm", b"salt", b"info", 64).unwrap();
    assert_eq!(okm1, okm2);
    assert_eq!(okm1.len(), 64);
    assert_ne!(okm1, vec![0u8; 64]);
}

/// `derive_to_vec` with `len = 0` must return an error.
#[test]
fn hkdf_sha256_derive_to_vec_zero_len_errors() {
    assert!(hkdf_sha256_derive_to_vec(b"ikm", b"salt", b"info", 0).is_err());
}
