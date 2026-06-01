//! Known-answer tests for SHA-256 (FIPS 180-4).
//!
//! Vectors from FIPS 180-4 Appendix B.1 and NIST CAVS.

use oxicrypto_core::Hash;
use oxicrypto_hash::Sha256;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha256_of(msg: &[u8]) -> String {
    let mut out = [0u8; 32];
    Sha256.hash(msg, &mut out).expect("sha256 hash failed");
    to_hex(&out)
}

/// FIPS 180-4: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
#[test]
fn sha256_empty() {
    assert_eq!(
        sha256_of(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 of empty string"
    );
}

/// FIPS 180-4 Appendix B.1: SHA-256("abc")
/// Verified: printf "abc" | sha256sum
#[test]
fn sha256_abc() {
    assert_eq!(
        sha256_of(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 of 'abc' (FIPS 180-4 Appendix B.1)"
    );
}

/// FIPS 180-4 Appendix B.2: SHA-256 of 448-bit message
/// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
/// Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
#[test]
fn sha256_448bit_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        sha256_of(msg),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "SHA-256 of 448-bit message (FIPS 180-4 Appendix B.2)"
    );
}

/// FIPS 180-4 Appendix B.3: SHA-256 of 896-bit message
/// "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
/// Expected: cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1
#[test]
fn sha256_896bit_message() {
    let msg =
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(
        sha256_of(msg),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        "SHA-256 of 896-bit message (FIPS 180-4 Appendix B.3)"
    );
}

/// Buffer-too-small returns an error without panicking.
#[test]
fn sha256_output_buffer_too_small() {
    let mut out = [0u8; 16];
    let result = Sha256.hash(b"test", &mut out);
    assert!(
        result.is_err(),
        "short output buffer should produce an error"
    );
}
