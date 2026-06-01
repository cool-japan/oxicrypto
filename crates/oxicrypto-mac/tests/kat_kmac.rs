//! Known-answer tests for KMAC128 and KMAC256 (NIST SP 800-185).
//!
//! Vectors from NIST SP 800-185 Appendix A, verified against tiny-keccak.

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
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── KMAC128 NIST SP 800-185 §A.1 ─────────────────────────────────────────────

/// NIST SP 800-185 §A.1 Sample #1 (KMAC128):
///
/// Key  = 404142434445464748494a4b4c4d4e4f
///        505152535455565758595a5b5c5d5e5f (32 bytes)
/// Data = 00010203 (4 bytes)
/// S    = "" (empty customization)
/// L    = 256 bits (32 bytes)
/// Expected = e5780b0d3ea6f7d3a429c5706aa43a00
///            fadbd7d49628839e3187243f456ee14e
#[test]
fn kmac128_nist_sp800_185_a1_sample1() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data = hex_decode("00010203");
    let expected = "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e";

    let kmac = Kmac128::new(b"", 32).expect("Kmac128::new failed");
    let mut out = [0u8; 32];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC128 §A.1 Sample #1 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "KMAC128 SP 800-185 §A.1 Sample #1 mismatch"
    );
}

/// NIST SP 800-185 §A.1 Sample #2 (KMAC128, non-empty customization):
///
/// Key  = 404142434445464748494a4b4c4d4e4f
///        505152535455565758595a5b5c5d5e5f (32 bytes)
/// Data = 00010203 (4 bytes)
/// S    = "My Tagged Application"
/// L    = 256 bits (32 bytes)
/// Expected = 3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5
#[test]
fn kmac128_nist_sp800_185_a1_sample2_with_customization() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data = hex_decode("00010203");
    let expected = "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5";

    let kmac = Kmac128::new(b"My Tagged Application", 32).expect("Kmac128::new failed");
    let mut out = [0u8; 32];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC128 §A.1 Sample #2 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "KMAC128 SP 800-185 §A.1 Sample #2 mismatch"
    );
}

/// NIST SP 800-185 §A.1 Sample #3 (KMAC128, 200-byte data):
///
/// Key  = 404142...5f (32 bytes)
/// Data = 0x00..0xc7 (200 bytes sequential)
/// S    = "My Tagged Application"
/// L    = 256 bits (32 bytes)
/// Expected = 1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230
#[test]
fn kmac128_nist_sp800_185_a1_sample3_200_byte_data() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data: Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let expected = "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230";

    let kmac = Kmac128::new(b"My Tagged Application", 32).expect("Kmac128::new failed");
    let mut out = [0u8; 32];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC128 §A.1 Sample #3 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "KMAC128 SP 800-185 §A.1 Sample #3 mismatch"
    );
}

// ── KMAC256 NIST SP 800-185 §A.2 ─────────────────────────────────────────────

/// NIST SP 800-185 §A.2 Sample #4 (KMAC256, empty customization, 64-byte output):
///
/// Key  = 404142...5f (32 bytes)
/// Data = 0x00..0xc7 (200 bytes sequential)
/// S    = "" (empty)
/// L    = 512 bits (64 bytes)
/// Expected = 75358cf39e41494e949707927cee0af2
///            0a3ff553904c86b08f21cc414bcfd691
///            589d27cf5e15369cbbff8b9a4c2eb178
///            00855d0235ff635da82533ec6b759b69
#[test]
fn kmac256_nist_sp800_185_a2_sample4_empty_customization() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data: Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let expected = concat!(
        "75358cf39e41494e949707927cee0af2",
        "0a3ff553904c86b08f21cc414bcfd691",
        "589d27cf5e15369cbbff8b9a4c2eb178",
        "00855d0235ff635da82533ec6b759b69",
    );

    let kmac = Kmac256::new(b"", 64).expect("Kmac256::new failed");
    let mut out = [0u8; 64];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC256 §A.2 Sample #4 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "KMAC256 SP 800-185 §A.2 Sample #4 mismatch"
    );
}

/// KMAC256, non-empty customization, 64-byte output:
///
/// Key  = 404142...5f (32 bytes)
/// Data = 0x00..0xc7 (200 bytes sequential)
/// S    = "My Tagged Application"
/// L    = 512 bits (64 bytes)
/// Expected computed by tiny-keccak (verified against SP 800-185 implementation):
/// b58618f71f92e1d56c1b8c55ddd7cd18
/// 8b97b4ca4d99831eb2699a837da2e4d9
/// 70fbacfde50033aea585f1a2708510c3
/// 2d07880801bd182898fe476876fc8965
#[test]
fn kmac256_nist_sp800_185_a2_sample5_with_customization() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data: Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let expected = concat!(
        "b58618f71f92e1d56c1b8c55ddd7cd18",
        "8b97b4ca4d99831eb2699a837da2e4d9",
        "70fbacfde50033aea585f1a2708510c3",
        "2d07880801bd182898fe476876fc8965",
    );

    let kmac = Kmac256::new(b"My Tagged Application", 64).expect("Kmac256::new failed");
    let mut out = [0u8; 64];
    kmac.mac(&key, &data, &mut out)
        .expect("KMAC256 §A.2 Sample #5 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "KMAC256 SP 800-185 §A.2 Sample #5 mismatch"
    );
}

/// Customization string changes the output.
#[test]
fn kmac128_customization_changes_output() {
    let key = [0x41_u8; 32];
    let data = b"same data";

    let kmac_empty = Kmac128::new(b"", 32).expect("new");
    let kmac_tagged = Kmac128::new(b"context", 32).expect("new");

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    kmac_empty.mac(&key, data, &mut out1).expect("mac1");
    kmac_tagged.mac(&key, data, &mut out2).expect("mac2");

    assert_ne!(
        out1, out2,
        "Different customization strings must produce different tags"
    );
}

/// Zero output_len is rejected.
#[test]
fn kmac128_zero_output_len_rejected() {
    assert!(
        Kmac128::new(b"", 0).is_err(),
        "output_len=0 must be rejected"
    );
}

/// Zero output_len is rejected for KMAC256.
#[test]
fn kmac256_zero_output_len_rejected() {
    assert!(
        Kmac256::new(b"", 0).is_err(),
        "output_len=0 must be rejected"
    );
}
