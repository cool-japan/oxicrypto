//! Known-answer tests for SHA-384 and SHA-512 (FIPS 180-4).
//!
//! Vectors from FIPS 180-4 Appendix B and verified with OpenSSL 3.x.

use oxicrypto_core::Hash;
use oxicrypto_hash::{Sha384, Sha512};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha384_of(msg: &[u8]) -> String {
    let mut out = [0u8; 48];
    Sha384.hash(msg, &mut out).expect("sha384 hash failed");
    to_hex(&out)
}

fn sha512_of(msg: &[u8]) -> String {
    let mut out = [0u8; 64];
    Sha512.hash(msg, &mut out).expect("sha512 hash failed");
    to_hex(&out)
}

// ── SHA-384 ──────────────────────────────────────────────────────────────────

/// FIPS 180-4: SHA-384("") = 38b060a7...
/// Verified: `printf "" | openssl dgst -sha384`
#[test]
fn sha384_empty() {
    assert_eq!(
        sha384_of(b""),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "SHA-384 of empty string (FIPS 180-4)"
    );
}

/// FIPS 180-4 Appendix B.3: SHA-384("abc")
/// Verified: `printf "abc" | openssl dgst -sha384`
#[test]
fn sha384_abc() {
    assert_eq!(
        sha384_of(b"abc"),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "SHA-384 of 'abc' (FIPS 180-4 Appendix B.3)"
    );
}

/// FIPS 180-4: SHA-384 of 448-bit message
/// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
/// Verified: `printf "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | openssl dgst -sha384`
#[test]
fn sha384_448bit_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        sha384_of(msg),
        "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
        "SHA-384 of 448-bit message (FIPS 180-4)"
    );
}

/// SHA-384 output length is 48 bytes.
#[test]
fn sha384_output_len() {
    assert_eq!(Sha384.output_len(), 48);
}

/// SHA-384 buffer-too-small returns an error.
#[test]
fn sha384_buffer_too_small() {
    let mut out = [0u8; 16];
    let result = Sha384.hash(b"test", &mut out);
    assert!(
        result.is_err(),
        "short output buffer should produce an error"
    );
}

// ── SHA-512 ──────────────────────────────────────────────────────────────────

/// FIPS 180-4: SHA-512("") = cf83e135...
/// Verified: `printf "" | openssl dgst -sha512`
#[test]
fn sha512_empty() {
    assert_eq!(
        sha512_of(b""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "SHA-512 of empty string (FIPS 180-4)"
    );
}

/// FIPS 180-4 Appendix B.4: SHA-512("abc")
/// Verified: `printf "abc" | openssl dgst -sha512`
#[test]
fn sha512_abc() {
    assert_eq!(
        sha512_of(b"abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "SHA-512 of 'abc' (FIPS 180-4 Appendix B.4)"
    );
}

/// FIPS 180-4: SHA-512 of 448-bit message
/// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
/// Verified: `printf "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | openssl dgst -sha512`
#[test]
fn sha512_448bit_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        sha512_of(msg),
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        "SHA-512 of 448-bit message (FIPS 180-4)"
    );
}

/// FIPS 180-4: SHA-512 of 896-bit message
/// "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
/// Verified: `printf "..." | openssl dgst -sha512`
#[test]
fn sha512_896bit_message() {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(
        sha512_of(msg),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        "SHA-512 of 896-bit message (FIPS 180-4)"
    );
}

/// SHA-512 output length is 64 bytes.
#[test]
fn sha512_output_len() {
    assert_eq!(Sha512.output_len(), 64);
}

/// SHA-512 buffer-too-small returns an error.
#[test]
fn sha512_buffer_too_small() {
    let mut out = [0u8; 16];
    let result = Sha512.hash(b"test", &mut out);
    assert!(
        result.is_err(),
        "short output buffer should produce an error"
    );
}

/// SHA-384 and SHA-512 are deterministic (same input always yields same output).
#[test]
fn sha384_sha512_deterministic() {
    let msg = b"determinism check";
    let a = sha384_of(msg);
    let b = sha384_of(msg);
    assert_eq!(a, b, "SHA-384 must be deterministic");

    let c = sha512_of(msg);
    let d = sha512_of(msg);
    assert_eq!(c, d, "SHA-512 must be deterministic");
}

/// SHA-384 and SHA-512 produce different outputs for different inputs.
#[test]
fn sha384_sha512_different_messages() {
    assert_ne!(sha384_of(b"message1"), sha384_of(b"message2"));
    assert_ne!(sha512_of(b"message1"), sha512_of(b"message2"));
}
