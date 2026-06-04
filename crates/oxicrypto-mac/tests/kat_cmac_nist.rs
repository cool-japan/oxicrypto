//! Known-answer tests for CMAC-AES-128 and CMAC-AES-256 (NIST SP 800-38B).
//!
//! Appendix D.1: CMAC-AES-128 test cases.
//! Appendix D.2: CMAC-AES-256 test cases.

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
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── CMAC-AES-128 (NIST SP 800-38B Appendix D.1) ──────────────────────────────

/// NIST SP 800-38B D.1 Example 1: AES-128, empty message.
///
/// K   = 2b7e151628aed2a6abf7158809cf4f3c
/// M   = (empty, 0 bytes)
/// T   = bb1d6929e95937287fa37d129b756746
#[test]
fn cmac_aes128_d1_tc1_empty_msg() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let expected = "bb1d6929e95937287fa37d129b756746";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, b"", &mut out)
        .expect("CMAC-AES-128 D.1 TC1 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.1 TC1 (empty msg) mismatch"
    );
}

/// NIST SP 800-38B D.1 Example 2: AES-128, 16-byte message.
///
/// K   = 2b7e151628aed2a6abf7158809cf4f3c
/// M   = 6bc1bee22e409f96e93d7e117393172a (16 bytes)
/// T   = 070a16b46b4d4144f79bdd9dd04a287c
#[test]
fn cmac_aes128_d1_tc2_16byte_msg() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = hex_decode("6bc1bee22e409f96e93d7e117393172a");
    let expected = "070a16b46b4d4144f79bdd9dd04a287c";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-128 D.1 TC2 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.1 TC2 (16-byte msg) mismatch"
    );
}

/// NIST SP 800-38B D.1 Example 3: AES-128, 40-byte message.
///
/// K   = 2b7e151628aed2a6abf7158809cf4f3c
/// M   = 6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
///       30c81c46a35ce411
/// T   = dfa66747de9ae63030ca32611497c827
#[test]
fn cmac_aes128_d1_tc3_40byte_msg() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = hex_decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411"
    ));
    let expected = "dfa66747de9ae63030ca32611497c827";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-128 D.1 TC3 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.1 TC3 (40-byte msg) mismatch"
    );
}

/// NIST SP 800-38B D.1 Example 4: AES-128, 64-byte message.
///
/// K   = 2b7e151628aed2a6abf7158809cf4f3c
/// M   = 6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
///       30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710
/// T   = 51f0bebf7e3b9d92fc49741779363cfe
#[test]
fn cmac_aes128_d1_tc4_64byte_msg() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = hex_decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710"
    ));
    let expected = "51f0bebf7e3b9d92fc49741779363cfe";

    let mut out = [0u8; 16];
    CmacAes128
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-128 D.1 TC4 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.1 TC4 (64-byte msg) mismatch"
    );
}

// ── CMAC-AES-256 (NIST SP 800-38B Appendix D.2) ──────────────────────────────

/// NIST SP 800-38B D.2 Example 1: AES-256, empty message.
///
/// K   = 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
/// M   = (empty, 0 bytes)
/// T   = 028962f61b7bf89efc6b551f4667d983
#[test]
fn cmac_aes256_d2_tc1_empty_msg() {
    let key = hex_decode(concat!(
        "603deb1015ca71be2b73aef0857d7781",
        "1f352c073b6108d72d9810a30914dff4"
    ));
    let expected = "028962f61b7bf89efc6b551f4667d983";

    let mut out = [0u8; 16];
    CmacAes256
        .mac(&key, b"", &mut out)
        .expect("CMAC-AES-256 D.2 TC1 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.2 TC1 (empty msg) mismatch"
    );
}

/// NIST SP 800-38B D.2 Example 2: AES-256, 16-byte message.
///
/// K   = 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
/// M   = 6bc1bee22e409f96e93d7e117393172a (16 bytes)
/// T   = 28a7023f452e8f82bd4bf28d8c37c35c
#[test]
fn cmac_aes256_d2_tc2_16byte_msg() {
    let key = hex_decode(concat!(
        "603deb1015ca71be2b73aef0857d7781",
        "1f352c073b6108d72d9810a30914dff4"
    ));
    let msg = hex_decode("6bc1bee22e409f96e93d7e117393172a");
    let expected = "28a7023f452e8f82bd4bf28d8c37c35c";

    let mut out = [0u8; 16];
    CmacAes256
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-256 D.2 TC2 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.2 TC2 (16-byte msg) mismatch"
    );
}

/// NIST SP 800-38B D.2 Example 3: AES-256, 40-byte message.
///
/// K   = 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
/// M   = 6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
///       30c81c46a35ce411
/// T   = aaf3d8f1de5640c232f5b169b9c911e6
#[test]
fn cmac_aes256_d2_tc3_40byte_msg() {
    let key = hex_decode(concat!(
        "603deb1015ca71be2b73aef0857d7781",
        "1f352c073b6108d72d9810a30914dff4"
    ));
    let msg = hex_decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411"
    ));
    let expected = "aaf3d8f1de5640c232f5b169b9c911e6";

    let mut out = [0u8; 16];
    CmacAes256
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-256 D.2 TC3 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.2 TC3 (40-byte msg) mismatch"
    );
}

/// NIST SP 800-38B D.2 Example 4: AES-256, 64-byte message.
///
/// K   = 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
/// M   = 6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
///       30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710
/// T   = e1992190549f6ed5696a2c056c315410
#[test]
fn cmac_aes256_d2_tc4_64byte_msg() {
    let key = hex_decode(concat!(
        "603deb1015ca71be2b73aef0857d7781",
        "1f352c073b6108d72d9810a30914dff4"
    ));
    let msg = hex_decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710"
    ));
    let expected = "e1992190549f6ed5696a2c056c315410";

    let mut out = [0u8; 16];
    CmacAes256
        .mac(&key, &msg, &mut out)
        .expect("CMAC-AES-256 D.2 TC4 failed");
    assert_eq!(
        to_hex(&out),
        expected,
        "NIST SP 800-38B D.2 TC4 (64-byte msg) mismatch"
    );
}
