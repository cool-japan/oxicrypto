//! Known-answer tests for SHA3-256, SHA3-384, SHA3-512 (FIPS 202).
//!
//! Vectors from FIPS 202 and verified with OpenSSL 3.x.

use oxicrypto_core::Hash;
use oxicrypto_hash::{Sha3_256, Sha3_384, Sha3_512};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha3_256_of(msg: &[u8]) -> String {
    let mut out = [0u8; 32];
    Sha3_256.hash(msg, &mut out).expect("sha3-256 hash failed");
    to_hex(&out)
}

fn sha3_384_of(msg: &[u8]) -> String {
    let mut out = [0u8; 48];
    Sha3_384.hash(msg, &mut out).expect("sha3-384 hash failed");
    to_hex(&out)
}

fn sha3_512_of(msg: &[u8]) -> String {
    let mut out = [0u8; 64];
    Sha3_512.hash(msg, &mut out).expect("sha3-512 hash failed");
    to_hex(&out)
}

// ── SHA3-256 ─────────────────────────────────────────────────────────────────

/// FIPS 202: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
/// Verified: `printf "" | openssl dgst -sha3-256`
#[test]
fn sha3_256_empty() {
    assert_eq!(
        sha3_256_of(b""),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "SHA3-256 of empty string (FIPS 202)"
    );
}

/// SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
/// Verified: `printf "abc" | openssl dgst -sha3-256`
#[test]
fn sha3_256_abc() {
    assert_eq!(
        sha3_256_of(b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA3-256 of 'abc' (FIPS 202)"
    );
}

/// SHA3-256 output length is 32 bytes.
#[test]
fn sha3_256_output_len() {
    assert_eq!(Sha3_256.output_len(), 32);
}

// ── SHA3-384 ─────────────────────────────────────────────────────────────────

/// FIPS 202: SHA3-384("") = 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61...
/// Verified: `printf "" | openssl dgst -sha3-384`
#[test]
fn sha3_384_empty() {
    assert_eq!(
        sha3_384_of(b""),
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        "SHA3-384 of empty string (FIPS 202)"
    );
}

/// SHA3-384("abc")
/// Verified: `printf "abc" | openssl dgst -sha3-384`
#[test]
fn sha3_384_abc() {
    assert_eq!(
        sha3_384_of(b"abc"),
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        "SHA3-384 of 'abc' (FIPS 202)"
    );
}

/// SHA3-384 output length is 48 bytes.
#[test]
fn sha3_384_output_len() {
    assert_eq!(Sha3_384.output_len(), 48);
}

// ── SHA3-512 ─────────────────────────────────────────────────────────────────

/// FIPS 202: SHA3-512("") = a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859...
/// Verified: `printf "" | openssl dgst -sha3-512`
#[test]
fn sha3_512_empty() {
    assert_eq!(
        sha3_512_of(b""),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        "SHA3-512 of empty string (FIPS 202)"
    );
}

/// SHA3-512("abc")
/// Verified: `printf "abc" | openssl dgst -sha3-512`
#[test]
fn sha3_512_abc() {
    assert_eq!(
        sha3_512_of(b"abc"),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        "SHA3-512 of 'abc' (FIPS 202)"
    );
}

/// SHA3-512 output length is 64 bytes.
#[test]
fn sha3_512_output_len() {
    assert_eq!(Sha3_512.output_len(), 64);
}

/// SHA3 hash is deterministic (same input always yields same output).
#[test]
fn sha3_256_deterministic() {
    let msg = b"determinism test";
    let a = sha3_256_of(msg);
    let b = sha3_256_of(msg);
    assert_eq!(a, b, "SHA3-256 must be deterministic");
}

/// Different messages must produce different digests.
#[test]
fn sha3_256_different_messages() {
    let a = sha3_256_of(b"message1");
    let b = sha3_256_of(b"message2");
    assert_ne!(a, b, "SHA3-256 of different messages must differ");
}
