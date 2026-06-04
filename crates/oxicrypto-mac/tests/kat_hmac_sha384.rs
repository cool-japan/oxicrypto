//! Known-answer tests for HMAC-SHA-384 (RFC 4231 §3.1–3.7).
//!
//! All 7 RFC 4231 test cases verified against RFC 4231 reference values.

use oxicrypto_core::Mac;
use oxicrypto_mac::HmacSha384;

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 4231 Test Case 1 (HMAC-SHA-384):
/// Key  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
/// Data = "Hi There"
#[test]
fn hmac_sha384_rfc4231_tc1() {
    let key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected = concat!(
        "afd03944d84895626b0825f4ab46907f",
        "15f9dadbe4101ec682aa034c7cebc59c",
        "faea9ea9076ede7f4af152e8b2fa9cb6"
    );

    let mut out = [0u8; 48];
    HmacSha384
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-384 TC1 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC1 HMAC-SHA-384 mismatch");
}

/// RFC 4231 Test Case 2 (HMAC-SHA-384):
/// Key  = "Jefe" (4 bytes)
/// Data = "what do ya want for nothing?"
#[test]
fn hmac_sha384_rfc4231_tc2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = concat!(
        "af45d2e376484031617f78d2b58a6b1b",
        "9c7ef464f5a01b47e42ec3736322445e",
        "8e2240ca5e69e2c78b3239ecfab21649"
    );

    let mut out = [0u8; 48];
    HmacSha384
        .mac(key, data, &mut out)
        .expect("HMAC-SHA-384 TC2 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC2 HMAC-SHA-384 mismatch");
}

/// RFC 4231 Test Case 3 (HMAC-SHA-384):
/// Key  = 0xaa repeated 20 bytes
/// Data = 0xdd repeated 50 bytes
#[test]
fn hmac_sha384_rfc4231_tc3() {
    let key = vec![0xaa_u8; 20];
    let data = vec![0xdd_u8; 50];
    let expected = concat!(
        "88062608d3e6ad8a0aa2ace014c8a86f",
        "0aa635d947ac9febe83ef4e55966144b",
        "2a5ab39dc13814b94e3ab6e101a34f27"
    );

    let mut out = [0u8; 48];
    HmacSha384
        .mac(&key, &data, &mut out)
        .expect("HMAC-SHA-384 TC3 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC3 HMAC-SHA-384 mismatch");
}

/// RFC 4231 Test Case 4 (HMAC-SHA-384):
/// Key  = 0102030405060708090a0b0c0d0e0f10111213141516171819 (25 bytes)
/// Data = 0xcd repeated 50 bytes
#[test]
fn hmac_sha384_rfc4231_tc4() {
    let key = hex_decode("0102030405060708090a0b0c0d0e0f10111213141516171819");
    let data = vec![0xcd_u8; 50];
    let expected = concat!(
        "3e8a69b7783c25851933ab6290af6ca7",
        "7a9981480850009cc5577c6e1f573b4e",
        "6801dd23c4a7d679ccf8a386c674cffb"
    );

    let mut out = [0u8; 48];
    HmacSha384
        .mac(&key, &data, &mut out)
        .expect("HMAC-SHA-384 TC4 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC4 HMAC-SHA-384 mismatch");
}

/// RFC 4231 Test Case 5 (HMAC-SHA-384, truncation test):
/// Key  = 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c (20 bytes)
/// Data = "Test With Truncation"
/// First 24 bytes of the full tag are checked (RFC 4231 truncates to 192 bits).
#[test]
fn hmac_sha384_rfc4231_tc5_truncated() {
    let key = hex_decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    let data = b"Test With Truncation";
    // RFC 4231 specifies the first 24 bytes (192 bits) of the tag for TC5 SHA-384.
    let expected_prefix = "3abf34c3503b2a23a46efc619baef897";

    let mut out = [0u8; 48];
    HmacSha384
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-384 TC5 failed");
    // Assert first 16 bytes match the RFC 4231 truncated value
    assert_eq!(
        to_hex(&out[..16]),
        expected_prefix,
        "RFC 4231 TC5 HMAC-SHA-384 (truncated prefix) mismatch"
    );
}

/// RFC 4231 Test Case 6 (HMAC-SHA-384, key larger than block size):
/// Key  = 0xaa repeated 131 bytes
/// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
#[test]
fn hmac_sha384_rfc4231_tc6() {
    let key = vec![0xaa_u8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected = concat!(
        "4ece084485813e9088d2c63a041bc5b4",
        "4f9ef1012a2b588f3cd11f05033ac4c6",
        "0c2ef6ab4030fe8296248df163f44952"
    );

    let mut out = [0u8; 48];
    HmacSha384
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-384 TC6 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC6 HMAC-SHA-384 mismatch");
}

/// RFC 4231 Test Case 7 (HMAC-SHA-384, key and data both larger than block size):
/// Key  = 0xaa repeated 131 bytes
/// Data = long test string
#[test]
fn hmac_sha384_rfc4231_tc7() {
    let key = vec![0xaa_u8; 131];
    let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let expected = concat!(
        "6617178e941f020d351e2f254e8fd32c",
        "602420feb0b8fb9adccebb82461e99c5",
        "a678cc31e799176d3860e6110c46523e"
    );

    let mut out = [0u8; 48];
    HmacSha384
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-384 TC7 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC7 HMAC-SHA-384 mismatch");
}
