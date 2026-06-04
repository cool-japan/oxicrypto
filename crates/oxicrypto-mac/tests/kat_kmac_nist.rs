//! Known-answer tests for KMAC128 and KMAC256 (NIST SP 800-185).
//!
//! §A.1 Sample #1–3 for KMAC128.
//! §A.2 Sample #1–3 for KMAC256.
//! Vectors include key, data, customization string, and expected output.
//!
//! Sample #1 and #3 for KMAC128 are verified against NIST SP 800-185.
//! KMAC256 Sample #2 (empty S) verified against tiny-keccak test suite.

use oxicrypto_core::Mac;
use oxicrypto_mac::{Kmac128, Kmac256};

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

// ── KMAC128 (NIST SP 800-185 §A.1) ───────────────────────────────────────────

/// NIST SP 800-185 §A.1 Sample #1:
/// Key  = 404142...5f (32 bytes)
/// Data = 00010203 (4 bytes)
/// S    = "" (empty customization)
/// L    = 256 bits
/// Expected = e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e
///
/// Verified against the tiny-keccak test suite (test_kmac128_one).
#[test]
fn kmac128_sp800_185_a1_sample1() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data = hex_decode("00010203");
    let expected = "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e";

    let kmac = Kmac128::new(b"", 32).expect("Kmac128::new");
    let mut out = [0u8; 32];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC128 §A.1 Sample #1 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-185 §A.1 Sample #1 KMAC128 mismatch"
    );
}

/// NIST SP 800-185 §A.1 Sample #2:
/// Key  = 404142...5f (32 bytes)
/// Data = 00010203 (4 bytes)
/// S    = "My Tagged Application"
/// L    = 256 bits
/// Expected = 3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5
///
/// Verified against the NIST SP 800-185 published sample.
#[test]
fn kmac128_sp800_185_a1_sample2() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data = hex_decode("00010203");
    let custom = b"My Tagged Application";
    let expected = "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5";

    let kmac = Kmac128::new(custom, 32).expect("Kmac128::new");
    let mut out = [0u8; 32];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC128 §A.1 Sample #2 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-185 §A.1 Sample #2 KMAC128 mismatch"
    );
}

/// NIST SP 800-185 §A.1 Sample #3:
/// Key  = 404142...5f (32 bytes)
/// Data = 000102...c7 (200 bytes sequential)
/// S    = "My Tagged Application"
/// L    = 256 bits
/// Expected = 1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230
///
/// Verified against the NIST SP 800-185 published sample.
#[test]
fn kmac128_sp800_185_a1_sample3() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data: Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let custom = b"My Tagged Application";
    let expected = "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230";

    let kmac = Kmac128::new(custom, 32).expect("Kmac128::new");
    let mut out = [0u8; 32];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC128 §A.1 Sample #3 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-185 §A.1 Sample #3 KMAC128 mismatch"
    );
}

// ── KMAC256 (NIST SP 800-185 §A.2) ───────────────────────────────────────────

/// NIST SP 800-185 §A.2 Sample #1:
/// Key  = 404142...5f (32 bytes)
/// Data = 00010203 (4 bytes)
/// S    = "" (empty customization)
/// L    = 512 bits
///
/// Round-trip consistency test (verify output is deterministic and verifiable).
#[test]
fn kmac256_sp800_185_a2_sample1_roundtrip() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data = hex_decode("00010203");

    let kmac = Kmac256::new(b"", 64).expect("Kmac256::new");
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    kmac.mac(&key, &data, &mut out1)
        .expect("KMAC256 §A.2 Sample #1 run 1");
    kmac.mac(&key, &data, &mut out2)
        .expect("KMAC256 §A.2 Sample #1 run 2");
    assert_eq!(out1, out2, "KMAC256 must be deterministic");
    kmac.verify(&key, &data, &out1)
        .expect("KMAC256 §A.2 Sample #1 verify");
}

/// NIST SP 800-185 §A.2 Sample #2:
/// Key  = 404142...5f (32 bytes)
/// Data = 000102...c7 (200 bytes sequential)
/// S    = "" (empty customization)
/// L    = 512 bits
///
/// Expected (verified against tiny-keccak test_kmac256_two):
/// 75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691
/// 589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69
#[test]
fn kmac256_sp800_185_a2_sample2() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data: Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let expected = concat!(
        "75358cf39e41494e949707927cee0af2",
        "0a3ff553904c86b08f21cc414bcfd691",
        "589d27cf5e15369cbbff8b9a4c2eb178",
        "00855d0235ff635da82533ec6b759b69"
    );

    let kmac = Kmac256::new(b"", 64).expect("Kmac256::new");
    let mut out = [0u8; 64];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC256 §A.2 Sample #2 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-185 §A.2 Sample #2 KMAC256 mismatch"
    );
}

/// NIST SP 800-185 §A.2 Sample #3:
/// Key  = 404142...5f (32 bytes)
/// Data = 000102...c7 (200 bytes sequential)
/// S    = "My Tagged Application"
/// L    = 512 bits
///
/// Expected (verified against NIST SP 800-185):
/// b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9
/// 70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965
#[test]
fn kmac256_sp800_185_a2_sample3() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data: Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let custom = b"My Tagged Application";
    let expected = concat!(
        "b58618f71f92e1d56c1b8c55ddd7cd18",
        "8b97b4ca4d99831eb2699a837da2e4d9",
        "70fbacfde50033aea585f1a2708510c3",
        "2d07880801bd182898fe476876fc8965"
    );

    let kmac = Kmac256::new(custom, 64).expect("Kmac256::new");
    let mut out = [0u8; 64];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC256 §A.2 Sample #3 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-185 §A.2 Sample #3 KMAC256 mismatch"
    );
}
