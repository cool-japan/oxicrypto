//! Known-answer tests for CMAC-AES-128 and CMAC-AES-256.
//!
//! Vectors from NIST SP 800-38B Appendix D.1 (AES-128) and D.2 (AES-256).
//! Example 1 (empty message) already verified by the inline tests.

use oxicrypto_core::Mac;
use oxicrypto_mac::{CmacAes128, CmacAes256};

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

// ── CMAC-AES-128 NIST SP 800-38B Appendix D.1 ───────────────────────────────

/// NIST SP 800-38B D.1 Example 1: AES-128, empty message.
///
/// K = 2b7e151628aed2a6abf7158809cf4f3c
/// M = (empty)
/// T = bb1d6929e95937287fa37d129b756746
#[test]
fn cmac_aes128_nist_sp800_38b_d1_example1_empty() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let expected = "bb1d6929e95937287fa37d129b756746";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, b"", &mut out)
        .expect("CMAC-AES-128 Ex1 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "CMAC-AES-128 SP 800-38B D.1 Ex1 (empty) mismatch"
    );
}

/// NIST SP 800-38B D.1 Example 2: AES-128, 16-byte message.
///
/// K = 2b7e151628aed2a6abf7158809cf4f3c
/// M = 6bc1bee22e409f96e93d7e117393172a (16 bytes)
/// T = 070a16b46b4d4144f79bdd9dd04a287c
#[test]
fn cmac_aes128_nist_sp800_38b_d1_example2_one_block() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = hex_decode("6bc1bee22e409f96e93d7e117393172a");
    let expected = "070a16b46b4d4144f79bdd9dd04a287c";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-128 Ex2 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "CMAC-AES-128 SP 800-38B D.1 Ex2 (16-byte) mismatch"
    );
}

/// NIST SP 800-38B D.1 Example 3: AES-128, 40-byte message.
///
/// K = 2b7e151628aed2a6abf7158809cf4f3c
/// M = 6bc1bee22e409f96e93d7e117393172a
///     ae2d8a571e03ac9c9eb76fac45af8e51
///     30c81c46a35ce411 (40 bytes total)
/// T = dfa66747de9ae63030ca32611497c827
#[test]
fn cmac_aes128_nist_sp800_38b_d1_example3_partial_block() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = hex_decode(
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411",
    );
    let expected = "dfa66747de9ae63030ca32611497c827";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-128 Ex3 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "CMAC-AES-128 SP 800-38B D.1 Ex3 (40-byte) mismatch"
    );
}

/// NIST SP 800-38B D.1 Example 4: AES-128, 64-byte message.
///
/// K = 2b7e151628aed2a6abf7158809cf4f3c
/// M = 6bc1bee22e409f96e93d7e117393172a
///     ae2d8a571e03ac9c9eb76fac45af8e51
///     30c81c46a35ce411e5fbc1191a0a52ef
///     f69f2445df4f9b17ad2b417be66c3710 (64 bytes)
/// T = 51f0bebf7e3b9d92fc49741779363cfe
#[test]
fn cmac_aes128_nist_sp800_38b_d1_example4_four_blocks() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = hex_decode(
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52ef\
         f69f2445df4f9b17ad2b417be66c3710",
    );
    let expected = "51f0bebf7e3b9d92fc49741779363cfe";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-128 Ex4 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "CMAC-AES-128 SP 800-38B D.1 Ex4 (64-byte) mismatch"
    );
}

// ── CMAC-AES-256 NIST SP 800-38B Appendix D.2 ───────────────────────────────

/// CMAC-AES-256, empty message.
///
/// K = 603deb1015ca71be2b73aef0857d7781
///     1f352c073b6108d72d9810a30914dff4
/// M = (empty)
/// T = 028962f61b7bf89efc6b551f4667d983
/// Verified: `openssl mac -macopt cipher:AES-256-CBC -macopt hexkey:<K> -in /dev/null CMAC`
#[test]
fn cmac_aes256_nist_sp800_38b_d2_example1_empty() {
    let key = hex_decode(
        "603deb1015ca71be2b73aef0857d7781\
         1f352c073b6108d72d9810a30914dff4",
    );
    let expected = "028962f61b7bf89efc6b551f4667d983";

    let mut out = [0u8; 16];
    CmacAes256
        .mac(&key, b"", &mut out)
        .expect("CMAC-AES-256 Ex1 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "CMAC-AES-256 SP 800-38B D.2 Ex1 (empty) mismatch"
    );
}

/// NIST SP 800-38B D.2 Example 4: AES-256, 64-byte message.
///
/// K = 603deb1015ca71be2b73aef0857d7781
///     1f352c073b6108d72d9810a30914dff4
/// M = 6bc1bee22e409f96e93d7e117393172a
///     ae2d8a571e03ac9c9eb76fac45af8e51
///     30c81c46a35ce411e5fbc1191a0a52ef
///     f69f2445df4f9b17ad2b417be66c3710
/// T = e1992190549f6ed5696a2c056c315410
#[test]
fn cmac_aes256_nist_sp800_38b_d2_example4_four_blocks() {
    let key = hex_decode(
        "603deb1015ca71be2b73aef0857d7781\
         1f352c073b6108d72d9810a30914dff4",
    );
    let msg = hex_decode(
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52ef\
         f69f2445df4f9b17ad2b417be66c3710",
    );
    let expected = "e1992190549f6ed5696a2c056c315410";

    let mut out = [0u8; 16];
    CmacAes256
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-256 Ex4 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "CMAC-AES-256 SP 800-38B D.2 Ex4 (64-byte) mismatch"
    );
}

/// CMAC verification rejects a corrupted tag.
#[test]
fn cmac_aes128_verify_rejects_tampered_tag() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = b"test data";

    let mut tag = [0u8; 16];
    CmacAes128.mac(&key, msg, &mut tag).expect("CMAC compute");
    tag[0] ^= 1;
    assert!(
        CmacAes128.verify(&key, msg, &tag).is_err(),
        "corrupted tag must be rejected"
    );
}
