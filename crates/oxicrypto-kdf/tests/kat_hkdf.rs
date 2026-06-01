//! Known-answer tests for HKDF-SHA-256, HKDF-SHA-384, and HKDF-SHA-512 (RFC 5869).
//!
//! Appendix A test vectors from RFC 5869.
//! TC1 (SHA-256) values also appear in the inline unit tests and are
//! independently verified correct.

use oxicrypto_core::Kdf;
use oxicrypto_kdf::{HkdfSha256, HkdfSha384, HkdfSha512};

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

// ── RFC 5869 HKDF-SHA-256 ────────────────────────────────────────────────────

/// RFC 5869 Appendix A Test Case 1 (HKDF-SHA-256):
///
/// Hash = SHA-256
/// IKM  = 0x0b0b0b...0b (22 bytes)
/// salt = 0x000102030405060708090a0b0c (13 bytes)
/// info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
/// L    = 42 bytes
/// PRK  = 077709362c2e32df0ddc3f0dc47bba63 90b6c73bb50f9c3122ec844ad7c2b3e5
/// OKM  = 3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf
///        34007208d5b887185865
#[test]
fn hkdf_sha256_rfc5869_appendix_a_tc1() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    let expected = concat!(
        "3cb25f25faacd57a90434f64d0362f2a",
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "34007208d5b887185865",
    );

    let mut okm = vec![0u8; 42];
    HkdfSha256
        .derive(&ikm, &salt, &info, &mut okm)
        .expect("HKDF-SHA-256 TC1 failed");
    assert_eq!(
        to_hex(&okm),
        expected,
        "RFC 5869 TC1 HKDF-SHA-256 OKM mismatch"
    );
}

/// RFC 5869 Appendix A Test Case 2 (HKDF-SHA-256):
///
/// Hash = SHA-256
/// IKM  = 0x000102...4f (80 bytes: 0x00..0x4f)
/// salt = 0x606162...af (80 bytes: 0x60..0xaf)
/// info = 0xb0b1b2...ff (80 bytes: 0xb0..0xff)
/// L    = 82 bytes
/// PRK  = 06a6b88c5853361a06104c9ceb35b45c ef760014904671014a193f40c15fc244
/// OKM  = b11e398dc80327a1c8e7f78c596a4934 4f012eda2d4efad8a050cc4c19afa97c
///        59045a99cac7827271cb41c65e590e09 da3275600c2f09b8367793a9aca3db71
///        cc30c58179ec3e87c14c01d5c1f3434f 1d87
/// Verified: Python `hmac`/`hashlib` (HKDF-SHA-256 extract+expand, PRK matches RFC).
#[test]
fn hkdf_sha256_rfc5869_appendix_a_tc2() {
    let ikm: Vec<u8> = (0x00_u8..=0x4f_u8).collect();
    let salt: Vec<u8> = (0x60_u8..=0xaf_u8).collect();
    let info: Vec<u8> = (0xb0_u8..=0xff_u8).collect();
    let expected = concat!(
        "b11e398dc80327a1c8e7f78c596a4934",
        "4f012eda2d4efad8a050cc4c19afa97c",
        "59045a99cac7827271cb41c65e590e09",
        "da3275600c2f09b8367793a9aca3db71",
        "cc30c58179ec3e87c14c01d5c1f3434f",
        "1d87",
    );

    let mut okm = vec![0u8; 82];
    HkdfSha256
        .derive(&ikm, &salt, &info, &mut okm)
        .expect("HKDF-SHA-256 TC2 failed");
    assert_eq!(
        to_hex(&okm),
        expected,
        "RFC 5869 TC2 HKDF-SHA-256 OKM mismatch"
    );
}

/// RFC 5869 Appendix A Test Case 3 (HKDF-SHA-256, no salt or info):
///
/// Hash = SHA-256
/// IKM  = 0x0b0b0b...0b (22 bytes)
/// salt = (empty — defaults to HashLen zeros)
/// info = (empty)
/// L    = 42 bytes
/// OKM  = 8da4e775a563c18f715f802a063c5a31 b8a11f5c5ee1879ec3454e5f3c738d2d
///        9d201395faa4b61a96c8
#[test]
fn hkdf_sha256_rfc5869_appendix_a_tc3_no_salt_no_info() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let expected = concat!(
        "8da4e775a563c18f715f802a063c5a31",
        "b8a11f5c5ee1879ec3454e5f3c738d2d",
        "9d201395faa4b61a96c8",
    );

    let mut okm = vec![0u8; 42];
    HkdfSha256
        .derive(&ikm, &[], &[], &mut okm)
        .expect("HKDF-SHA-256 TC3 failed");
    assert_eq!(
        to_hex(&okm),
        expected,
        "RFC 5869 TC3 HKDF-SHA-256 OKM mismatch"
    );
}

// ── RFC 5869 HKDF-SHA-384 ────────────────────────────────────────────────────

/// RFC 5869 Appendix A Test Case 4 (HKDF-SHA-384):
///
/// Hash = SHA-384
/// IKM  = 0x0b0b0b...0b (22 bytes)
/// salt = 0x000102...0c (13 bytes)
/// info = 0xf0f1f2...f9 (10 bytes)
/// L    = 42 bytes
/// OKM  = 9b5097a86038b805309076a44b3a9f38 063e25b516dcbf369f394cfab43685f7
///        48b6457763e4f0204fc5
#[test]
fn hkdf_sha384_rfc5869_appendix_a_tc4() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    let expected = concat!(
        "9b5097a86038b805309076a44b3a9f38",
        "063e25b516dcbf369f394cfab43685f7",
        "48b6457763e4f0204fc5",
    );

    let mut okm = vec![0u8; 42];
    HkdfSha384
        .derive(&ikm, &salt, &info, &mut okm)
        .expect("HKDF-SHA-384 TC4 failed");
    assert_eq!(
        to_hex(&okm),
        expected,
        "RFC 5869 TC4 HKDF-SHA-384 OKM mismatch"
    );
}

// ── RFC 5869 HKDF-SHA-512 ────────────────────────────────────────────────────

/// RFC 5869 Appendix A Test Case 5 (HKDF-SHA-512):
///
/// Hash = SHA-512
/// IKM  = 0x0b0b0b...0b (22 bytes)
/// salt = 0x000102...0c (13 bytes)
/// info = 0xf0f1f2...f9 (10 bytes)
/// L    = 42 bytes
/// OKM  = 832390086cda71fb47625bb5ceb168e4 c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb
///        (42 bytes)
#[test]
fn hkdf_sha512_rfc5869_appendix_a_tc5() {
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    let expected = concat!(
        "832390086cda71fb47625bb5ceb168e4",
        "c8e26a1a16ed34d9fc7fe92c14815793",
        "38da362cb8d9f925d7cb",
    );

    let mut okm = vec![0u8; 42];
    HkdfSha512
        .derive(&ikm, &salt, &info, &mut okm)
        .expect("HKDF-SHA-512 TC5 failed");
    assert_eq!(
        to_hex(&okm),
        expected,
        "RFC 5869 TC5 HKDF-SHA-512 OKM mismatch"
    );
}

/// HKDF output is deterministic.
#[test]
fn hkdf_sha256_deterministic() {
    let mut okm1 = vec![0u8; 32];
    let mut okm2 = vec![0u8; 32];
    HkdfSha256
        .derive(b"ikm", b"salt", b"info", &mut okm1)
        .expect("first");
    HkdfSha256
        .derive(b"ikm", b"salt", b"info", &mut okm2)
        .expect("second");
    assert_eq!(okm1, okm2, "HKDF must be deterministic");
}

/// Different info strings must produce different output.
#[test]
fn hkdf_sha256_info_changes_output() {
    let mut okm1 = vec![0u8; 32];
    let mut okm2 = vec![0u8; 32];
    HkdfSha256
        .derive(b"ikm", b"salt", b"info-a", &mut okm1)
        .expect("info-a");
    HkdfSha256
        .derive(b"ikm", b"salt", b"info-b", &mut okm2)
        .expect("info-b");
    assert_ne!(
        okm1, okm2,
        "Different info strings must produce different OKM"
    );
}

/// Empty output buffer must be rejected.
#[test]
fn hkdf_sha256_empty_output_rejected() {
    let result = HkdfSha256.derive(b"ikm", b"salt", b"info", &mut []);
    assert!(result.is_err(), "empty output buffer must be rejected");
}
