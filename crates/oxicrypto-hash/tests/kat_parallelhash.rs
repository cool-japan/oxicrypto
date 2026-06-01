//! Known-answer tests for ParallelHash128 / ParallelHash256 (NIST SP 800-185 §6).
//!
//! All vectors are the official NIST example values from the SP 800-185
//! "SHA-3 Derived Functions" sample document (`ParallelHash_samples.pdf`,
//! Computer Security Resource Center). Each sample fixes the input data `X`,
//! the block size `B`, the requested output length `L`, and the customization
//! string `S`, and the expected output ("Outval") is locked exactly.
//!
//! Samples covered:
//!   ParallelHash128 #1: B=8,  L=256, S=""             (data = 00..07 10..17 20..27)
//!   ParallelHash128 #2: B=8,  L=256, S="Parallel Data"
//!   ParallelHash128 #3: B=12, L=256, S="Parallel Data" (data = 00..0B 10..1B 20..2B 30..3B 40..4B 50..5B)
//!   ParallelHash256 #1: B=8,  L=512, S=""
//!   ParallelHash256 #2: B=8,  L=512, S="Parallel Data"
//!   ParallelHash256 #3: B=12, L=512, S="Parallel Data"

use oxicrypto_hash::{parallel_hash128, parallel_hash256, ParallelHash128, ParallelHash256};

/// Sample data for #1/#2: 24 bytes `00..07 10..17 20..27`.
const DATA_24: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
];

/// Sample data for #3: 72 bytes `00..0B 10..1B 20..2B 30..3B 40..4B 50..5B`.
const DATA_72: [u8; 72] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, // 00..0B
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, // 10..1B
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, // 20..2B
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, // 30..3B
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, // 40..4B
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, // 50..5B
];

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

// ── ParallelHash128 (fixed output) ──────────────────────────────────────────

/// NIST SP 800-185 ParallelHash128 Sample #1: B=8, L=256, S="".
#[test]
fn parallel_hash128_sample1() {
    let mut out = [0u8; 32];
    parallel_hash128(&DATA_24, 8, b"", &mut out).unwrap();
    assert_eq!(
        to_hex(&out),
        "BA8DC1D1D979331D3F813603C67F72609AB5E44B94A0B8F9AF46514454A2B4F5",
        "ParallelHash128 Sample #1 (B=8, L=256, S=\"\")"
    );
}

/// NIST SP 800-185 ParallelHash128 Sample #2: B=8, L=256, S="Parallel Data".
#[test]
fn parallel_hash128_sample2() {
    let mut out = [0u8; 32];
    parallel_hash128(&DATA_24, 8, b"Parallel Data", &mut out).unwrap();
    assert_eq!(
        to_hex(&out),
        "FC484DCB3F84DCEEDC353438151BEE58157D6EFED0445A81F165E495795B7206",
        "ParallelHash128 Sample #2 (B=8, L=256, S=\"Parallel Data\")"
    );
}

/// NIST SP 800-185 ParallelHash128 Sample #3: B=12, L=256, S="Parallel Data".
#[test]
fn parallel_hash128_sample3() {
    let mut out = [0u8; 32];
    parallel_hash128(&DATA_72, 12, b"Parallel Data", &mut out).unwrap();
    assert_eq!(
        to_hex(&out),
        "F7FD5312896C6685C828AF7E2ADB97E393E7F8D54E3C2EA4B95E5ACA3796E8FC",
        "ParallelHash128 Sample #3 (B=12, L=256, S=\"Parallel Data\")"
    );
}

// ── ParallelHash256 (fixed output) ──────────────────────────────────────────

/// NIST SP 800-185 ParallelHash256 Sample #1: B=8, L=512, S="".
#[test]
fn parallel_hash256_sample1() {
    let mut out = [0u8; 64];
    parallel_hash256(&DATA_24, 8, b"", &mut out).unwrap();
    assert_eq!(
        to_hex(&out),
        "BC1EF124DA34495E948EAD207DD9842235DA432D2BBC54B4C110E64C45110553\
         1B7F2A3E0CE055C02805E7C2DE1FB746AF97A1DD01F43B824E31B87612410429",
        "ParallelHash256 Sample #1 (B=8, L=512, S=\"\")"
    );
}

/// NIST SP 800-185 ParallelHash256 Sample #2: B=8, L=512, S="Parallel Data".
#[test]
fn parallel_hash256_sample2() {
    let mut out = [0u8; 64];
    parallel_hash256(&DATA_24, 8, b"Parallel Data", &mut out).unwrap();
    assert_eq!(
        to_hex(&out),
        "CDF15289B54F6212B4BC270528B49526006DD9B54E2B6ADD1EF6900DDA3963BB\
         33A72491F236969CA8AFAEA29C682D47A393C065B38E29FAE651A2091C833110",
        "ParallelHash256 Sample #2 (B=8, L=512, S=\"Parallel Data\")"
    );
}

/// NIST SP 800-185 ParallelHash256 Sample #3: B=12, L=512, S="Parallel Data".
#[test]
fn parallel_hash256_sample3() {
    let mut out = [0u8; 64];
    parallel_hash256(&DATA_72, 12, b"Parallel Data", &mut out).unwrap();
    assert_eq!(
        to_hex(&out),
        "69D0FCB764EA055DD09334BC6021CB7E4B61348DFF375DA262671CDEC3EFFA8D\
         1B4568A6CCE16B1CAD946DDDE27F6CE2B8DEE4CD1B24851EBF00EB90D43813E9",
        "ParallelHash256 Sample #3 (B=12, L=512, S=\"Parallel Data\")"
    );
}

// ── Struct API agrees with the official vectors ─────────────────────────────

/// The [`ParallelHash128`] struct wrapper reproduces Sample #2 exactly.
#[test]
fn parallel_hash128_struct_sample2() {
    let mut out = [0u8; 32];
    ParallelHash128::new(8, b"Parallel Data")
        .unwrap()
        .hash(&DATA_24, &mut out)
        .unwrap();
    assert_eq!(
        to_hex(&out),
        "FC484DCB3F84DCEEDC353438151BEE58157D6EFED0445A81F165E495795B7206",
        "ParallelHash128 struct must match Sample #2"
    );
}

/// The [`ParallelHash256`] struct wrapper reproduces Sample #3 exactly.
#[test]
fn parallel_hash256_struct_sample3() {
    let mut out = [0u8; 64];
    ParallelHash256::new(12, b"Parallel Data")
        .unwrap()
        .hash(&DATA_72, &mut out)
        .unwrap();
    assert_eq!(
        to_hex(&out),
        "69D0FCB764EA055DD09334BC6021CB7E4B61348DFF375DA262671CDEC3EFFA8D\
         1B4568A6CCE16B1CAD946DDDE27F6CE2B8DEE4CD1B24851EBF00EB90D43813E9",
        "ParallelHash256 struct must match Sample #3"
    );
}
