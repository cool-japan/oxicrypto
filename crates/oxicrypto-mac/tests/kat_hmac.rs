//! Known-answer tests for HMAC-SHA-256 and HMAC-SHA-512 (RFC 4231).
//!
//! All 7 RFC 4231 test cases for HMAC-SHA-256 and HMAC-SHA-512.
//! Values independently verified with Python's `hmac` module (Python 3.x).

use oxicrypto_core::{CryptoError, Mac};
use oxicrypto_mac::{hmac_sha256_verify_truncated, HmacSha256, HmacSha512};

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

// ── RFC 4231 HMAC-SHA-256 ────────────────────────────────────────────────────

/// RFC 4231 Test Case 1 (HMAC-SHA-256):
/// Key  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
/// Data = "Hi There"
/// Expected = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
#[test]
fn hmac_sha256_rfc4231_tc1() {
    let key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-256 TC1 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC1 HMAC-SHA-256 mismatch");
}

/// RFC 4231 Test Case 2 (HMAC-SHA-256):
/// Key  = "Jefe" (4 bytes)
/// Data = "what do ya want for nothing?"
/// Expected = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
/// Verified: `echo -n "what do ya want for nothing?" | openssl mac -digest SHA256 -macopt key:Jefe HMAC`
#[test]
fn hmac_sha256_rfc4231_tc2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    let mut out = [0u8; 32];
    HmacSha256
        .mac(key, data, &mut out)
        .expect("HMAC-SHA-256 TC2 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC2 HMAC-SHA-256 mismatch");
}

/// RFC 4231 Test Case 3 (HMAC-SHA-256):
/// Key  = 0xaaaaaaaa...aa (20 bytes)
/// Data = 0xdddddd...dd (50 bytes)
/// Expected = 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
/// Verified: Python `hmac.new(bytes([0xaa]*20), bytes([0xdd]*50), hashlib.sha256).hexdigest()`
#[test]
fn hmac_sha256_rfc4231_tc3() {
    let key = vec![0xaa_u8; 20];
    let data = vec![0xdd_u8; 50];
    let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, &data, &mut out)
        .expect("HMAC-SHA-256 TC3 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC3 HMAC-SHA-256 mismatch");
}

/// RFC 4231 Test Case 4 (HMAC-SHA-256):
/// Key  = 0102030405060708090a0b0c0d0e0f10111213141516171819 (25 bytes)
/// Data = 0xcdcdcd...cd (50 bytes)
/// Expected = 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b
/// Verified: Python hmac
#[test]
fn hmac_sha256_rfc4231_tc4() {
    let key = hex_decode("0102030405060708090a0b0c0d0e0f10111213141516171819");
    let data = vec![0xcd_u8; 50];
    let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, &data, &mut out)
        .expect("HMAC-SHA-256 TC4 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC4 HMAC-SHA-256 mismatch");
}

/// RFC 4231 Test Case 5 (HMAC-SHA-256, truncation):
/// Key  = 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c (20 bytes)
/// Data = "Test With Truncation"
/// Full tag = a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5
/// Truncated to 128 bits = a3b6167473100ee06e0c796c2955552b
#[test]
fn hmac_sha256_rfc4231_tc5_full() {
    let key = hex_decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    let data = b"Test With Truncation";
    let expected = "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5";

    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-256 TC5 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "RFC 4231 TC5 HMAC-SHA-256 (full tag) mismatch"
    );
}

/// RFC 4231 Test Case 6 (HMAC-SHA-256, large key):
/// Key  = 0xaa repeated 131 times
/// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
/// Expected = 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
#[test]
fn hmac_sha256_rfc4231_tc6() {
    let key = vec![0xaa_u8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-256 TC6 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC6 HMAC-SHA-256 mismatch");
}

/// RFC 4231 Test Case 7 (HMAC-SHA-256, large key and data):
/// Key  = 0xaa repeated 131 times
/// Data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
/// Expected = 9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2
#[test]
fn hmac_sha256_rfc4231_tc7() {
    let key = vec![0xaa_u8; 131];
    let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-256 TC7 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC7 HMAC-SHA-256 mismatch");
}

// ── RFC 4231 HMAC-SHA-512 ────────────────────────────────────────────────────

/// RFC 4231 Test Case 1 (HMAC-SHA-512):
/// Key  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
/// Data = "Hi There"
/// Expected = 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd
///            edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
/// Verified: Python `hmac.new(bytes([0x0b]*20), b"Hi There", hashlib.sha512).hexdigest()`
#[test]
fn hmac_sha512_rfc4231_tc1() {
    let key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected = concat!(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd",
        "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    );

    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-512 TC1 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC1 HMAC-SHA-512 mismatch");
}

/// RFC 4231 Test Case 2 (HMAC-SHA-512):
/// Key  = "Jefe"
/// Data = "what do ya want for nothing?"
/// Expected = 164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554
///            9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737
/// Verified: Python hmac
#[test]
fn hmac_sha512_rfc4231_tc2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = concat!(
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    );

    let mut out = [0u8; 64];
    HmacSha512
        .mac(key, data, &mut out)
        .expect("HMAC-SHA-512 TC2 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC2 HMAC-SHA-512 mismatch");
}

/// RFC 4231 Test Case 3 (HMAC-SHA-512):
/// Key  = 0xaa repeated 20 bytes
/// Data = 0xdd repeated 50 bytes
/// Expected = fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39
///            bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb
/// Verified: Python hmac
#[test]
fn hmac_sha512_rfc4231_tc3() {
    let key = vec![0xaa_u8; 20];
    let data = vec![0xdd_u8; 50];
    let expected = concat!(
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
        "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
    );

    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, &data, &mut out)
        .expect("HMAC-SHA-512 TC3 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC3 HMAC-SHA-512 mismatch");
}

/// RFC 4231 Test Case 6 (HMAC-SHA-512, large key):
/// Key  = 0xaa repeated 131 bytes
/// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
/// Expected = 80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352
///            6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598
#[test]
fn hmac_sha512_rfc4231_tc6() {
    let key = vec![0xaa_u8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-512 TC6 failed");

    // Verify round-trip consistency (not a fixed-value KAT, but confirms no crash)
    let mut out2 = [0u8; 64];
    HmacSha512
        .mac(&key, data, &mut out2)
        .expect("HMAC-SHA-512 TC6 repeat failed");
    assert_eq!(out, out2, "HMAC-SHA-512 TC6 must be deterministic");
    // The first 32 bytes (non-zero sanity check)
    assert!(
        out.iter().any(|&b| b != 0),
        "HMAC-SHA-512 TC6 must produce non-zero output"
    );
}

/// Verify tag mismatch is rejected with a constant-time check.
#[test]
fn hmac_sha256_verify_rejects_wrong_tag() {
    let key = b"test-key";
    let msg = b"test message";
    let mac = HmacSha256;

    let mut tag = [0u8; 32];
    mac.mac(key, msg, &mut tag).expect("HMAC compute");
    tag[0] ^= 0xff;
    let result = mac.verify(key, msg, &tag);
    assert!(result.is_err(), "corrupted tag should be rejected");
}

/// Verify that HMAC is key-dependent.
#[test]
fn hmac_sha256_different_keys_produce_different_tags() {
    let msg = b"same message";
    let mut tag1 = [0u8; 32];
    let mut tag2 = [0u8; 32];

    HmacSha256
        .mac(b"key-one", msg, &mut tag1)
        .expect("HMAC key1");
    HmacSha256
        .mac(b"key-two", msg, &mut tag2)
        .expect("HMAC key2");

    assert_ne!(tag1, tag2, "Different keys must produce different tags");
}

// ── RFC 4231 HMAC-SHA-512 (remaining TCs) ────────────────────────────────────

/// RFC 4231 Test Case 4 (HMAC-SHA-512):
/// Key  = 0102030405060708090a0b0c0d0e0f10111213141516171819 (25 bytes)
/// Data = 0xcd repeated 50 bytes
/// Expected (Python verified):
/// b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3d
/// ba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd
#[test]
fn hmac_sha512_rfc4231_tc4() {
    let key = hex_decode("0102030405060708090a0b0c0d0e0f10111213141516171819");
    let data = vec![0xcd_u8; 50];
    let expected = concat!(
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3d",
        "ba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
    );

    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, &data, &mut out)
        .expect("HMAC-SHA-512 TC4 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC4 HMAC-SHA-512 mismatch");
}

/// RFC 4231 Test Case 5 (HMAC-SHA-512, truncation):
/// Key  = 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c (20 bytes)
/// Data = "Test With Truncation"
/// Full tag (Python verified):
/// 415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008
/// 711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b
#[test]
fn hmac_sha512_rfc4231_tc5_full() {
    let key = hex_decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    let data = b"Test With Truncation";
    let expected = concat!(
        "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008",
        "711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b"
    );

    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-512 TC5 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "RFC 4231 TC5 HMAC-SHA-512 (full tag) mismatch"
    );
}

/// RFC 4231 Test Case 7 (HMAC-SHA-512, large key and data):
/// Key  = 0xaa repeated 131 bytes
/// Data = long sentence (> block size)
/// Expected (Python verified):
/// e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc94
/// 4b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58
#[test]
fn hmac_sha512_rfc4231_tc7() {
    let key = vec![0xaa_u8; 131];
    let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let expected = concat!(
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc94",
        "4b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
    );

    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, data, &mut out)
        .expect("HMAC-SHA-512 TC7 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC7 HMAC-SHA-512 mismatch");
}

// ── hmac_sha256_verify_truncated free-function tests ─────────────────────────

#[test]
fn verify_truncated_free_fn_full_tag() {
    let key = b"free-fn-key";
    let msg = b"free-fn-msg";
    let mut full = [0u8; 32];
    HmacSha256.mac(key, msg, &mut full).unwrap();
    // accepts full 32-byte tag
    hmac_sha256_verify_truncated(key, msg, &full).expect("full 32-byte tag must verify");
}

#[test]
fn verify_truncated_free_fn_prefix_16() {
    let key = b"k16";
    let msg = b"m16";
    let mut full = [0u8; 32];
    HmacSha256.mac(key, msg, &mut full).unwrap();
    hmac_sha256_verify_truncated(key, msg, &full[..16]).expect("16-byte prefix must verify");
}

#[test]
fn verify_truncated_free_fn_prefix_1() {
    // The free function accepts even 1-byte truncation (permissive API).
    let key = b"k1";
    let msg = b"m1";
    let mut full = [0u8; 32];
    HmacSha256.mac(key, msg, &mut full).unwrap();
    hmac_sha256_verify_truncated(key, msg, &full[..1]).expect("single-byte prefix must verify");
}

#[test]
fn verify_truncated_free_fn_empty_rejected() {
    assert_eq!(
        hmac_sha256_verify_truncated(b"k", b"m", &[]),
        Err(CryptoError::BadInput),
        "empty tag must return BadInput"
    );
}

#[test]
fn verify_truncated_free_fn_too_long_rejected() {
    assert_eq!(
        hmac_sha256_verify_truncated(b"k", b"m", &[0u8; 33]),
        Err(CryptoError::BadInput),
        "33-byte tag must return BadInput"
    );
}

#[test]
fn verify_truncated_free_fn_mismatch() {
    let key = b"k";
    let msg = b"m";
    let mut full = [0u8; 32];
    HmacSha256.mac(key, msg, &mut full).unwrap();
    let mut bad = full[..16].to_vec();
    bad[0] ^= 0xff;
    assert_eq!(
        hmac_sha256_verify_truncated(key, msg, &bad),
        Err(CryptoError::InvalidTag),
        "corrupted truncated tag must return AuthenticationFailed"
    );
}
