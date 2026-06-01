//! Known-answer tests for SHAKE128 / SHAKE256 (FIPS 202).
//!
//! Vectors verified with OpenSSL 3.x:
//!   `printf "" | openssl dgst -shake-128 -xoflen 32`
//!   `printf "abc" | openssl dgst -shake-128 -xoflen 32`
//!   `printf "" | openssl dgst -shake-256 -xoflen 64`
//!   `printf "abc" | openssl dgst -shake-256 -xoflen 64`
//!
//! cSHAKE and TupleHash property tests (unambiguity, customization, degradation to
//! SHAKE) are covered inline in `src/xof.rs`. This file adds explicit
//! digest-equality KATs for SHAKE128 and SHAKE256.

use oxicrypto_hash::{shake128, shake256};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── SHAKE128 ─────────────────────────────────────────────────────────────────

/// SHAKE128("", 32 bytes) — FIPS 202 / OpenSSL 3.x verified.
/// `printf "" | openssl dgst -shake-128 -xoflen 32`
#[test]
fn shake128_empty_32bytes() {
    let mut out = [0u8; 32];
    shake128(b"", &mut out);
    assert_eq!(
        to_hex(&out),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        "SHAKE128(empty, 32 bytes) (FIPS 202)"
    );
}

/// SHAKE128("abc", 32 bytes) — OpenSSL 3.x verified.
/// `printf "abc" | openssl dgst -shake-128 -xoflen 32`
#[test]
fn shake128_abc_32bytes() {
    let mut out = [0u8; 32];
    shake128(b"abc", &mut out);
    assert_eq!(
        to_hex(&out),
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
        "SHAKE128('abc', 32 bytes) (FIPS 202)"
    );
}

/// SHAKE128 output is a prefix extension: 32-byte output is a prefix of 64-byte output.
#[test]
fn shake128_prefix_consistency() {
    let msg = b"prefix test";
    let mut out32 = [0u8; 32];
    let mut out64 = [0u8; 64];
    shake128(msg, &mut out32);
    shake128(msg, &mut out64);
    assert_eq!(
        out32,
        out64[..32],
        "32-byte SHAKE128 output must be a prefix of 64-byte output"
    );
}

/// SHAKE128 is deterministic.
#[test]
fn shake128_deterministic() {
    let msg = b"determinism";
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    shake128(msg, &mut a);
    shake128(msg, &mut b);
    assert_eq!(a, b, "SHAKE128 must be deterministic");
}

/// SHAKE128 produces different outputs for different inputs.
#[test]
fn shake128_different_messages() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    shake128(b"message1", &mut a);
    shake128(b"message2", &mut b);
    assert_ne!(a, b, "SHAKE128 of different inputs must differ");
}

// ── SHAKE256 ─────────────────────────────────────────────────────────────────

/// SHAKE256("", 64 bytes) — OpenSSL 3.x verified.
/// `printf "" | openssl dgst -shake-256 -xoflen 64`
#[test]
fn shake256_empty_64bytes() {
    let mut out = [0u8; 64];
    shake256(b"", &mut out);
    assert_eq!(
        to_hex(&out),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        "SHAKE256(empty, 64 bytes) (FIPS 202)"
    );
}

/// SHAKE256("abc", 64 bytes) — OpenSSL 3.x verified.
/// `printf "abc" | openssl dgst -shake-256 -xoflen 64`
#[test]
fn shake256_abc_64bytes() {
    let mut out = [0u8; 64];
    shake256(b"abc", &mut out);
    assert_eq!(
        to_hex(&out),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
        "SHAKE256('abc', 64 bytes) (FIPS 202)"
    );
}

/// SHAKE256 output is a prefix extension: 32-byte output is a prefix of 64-byte output.
#[test]
fn shake256_prefix_consistency() {
    let msg = b"prefix test";
    let mut out32 = [0u8; 32];
    let mut out64 = [0u8; 64];
    shake256(msg, &mut out32);
    shake256(msg, &mut out64);
    assert_eq!(
        out32,
        out64[..32],
        "32-byte SHAKE256 output must be a prefix of 64-byte output"
    );
}

/// SHAKE256 is deterministic.
#[test]
fn shake256_deterministic() {
    let msg = b"determinism";
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    shake256(msg, &mut a);
    shake256(msg, &mut b);
    assert_eq!(a, b, "SHAKE256 must be deterministic");
}

/// SHAKE256 produces different outputs for different inputs.
#[test]
fn shake256_different_messages() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    shake256(b"message1", &mut a);
    shake256(b"message2", &mut b);
    assert_ne!(a, b, "SHAKE256 of different inputs must differ");
}

/// SHAKE128 and SHAKE256 produce different outputs for the same input
/// (they use different capacity / rate parameters per FIPS 202).
#[test]
fn shake128_and_shake256_differ() {
    let msg = b"same message";
    let mut s128 = [0u8; 32];
    let mut s256 = [0u8; 32];
    shake128(msg, &mut s128);
    shake256(msg, &mut s256);
    assert_ne!(
        s128, s256,
        "SHAKE128 and SHAKE256 outputs must differ (different capacity)"
    );
}
