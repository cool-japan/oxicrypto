//! Known-answer tests for BLAKE2b-256, BLAKE2b-512, and BLAKE2s-256 (RFC 7693).
//!
//! Vectors verified with Python 3 `hashlib` (which follows RFC 7693):
//!
//!   hashlib.blake2b(b"", digest_size=32).hexdigest()  => BLAKE2b-256("")
//!   hashlib.blake2b(b"", digest_size=64).hexdigest()  => BLAKE2b-512("")
//!   hashlib.blake2s(b"", digest_size=32).hexdigest()  => BLAKE2s-256("")
//!
//! RFC 7693 §A.1 gives BLAKE2b-512("") =
//!   786a02f7...be2ce (64 bytes).

use oxicrypto_core::Hash;
use oxicrypto_hash::{Blake2b256, Blake2b512, Blake2s256};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn blake2b256_of(msg: &[u8]) -> String {
    let mut out = [0u8; 32];
    Blake2b256
        .hash(msg, &mut out)
        .expect("blake2b-256 hash failed");
    to_hex(&out)
}

fn blake2b512_of(msg: &[u8]) -> String {
    let mut out = [0u8; 64];
    Blake2b512
        .hash(msg, &mut out)
        .expect("blake2b-512 hash failed");
    to_hex(&out)
}

fn blake2s256_of(msg: &[u8]) -> String {
    let mut out = [0u8; 32];
    Blake2s256
        .hash(msg, &mut out)
        .expect("blake2s-256 hash failed");
    to_hex(&out)
}

// ── BLAKE2b-256 ──────────────────────────────────────────────────────────────

/// BLAKE2b-256("") — RFC 7693 / Python hashlib verified.
/// hashlib.blake2b(b"", digest_size=32).hexdigest()
#[test]
fn blake2b256_empty() {
    assert_eq!(
        blake2b256_of(b""),
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        "BLAKE2b-256 of empty string (RFC 7693)"
    );
}

/// BLAKE2b-256("abc") — Python hashlib verified.
/// hashlib.blake2b(b"abc", digest_size=32).hexdigest()
#[test]
fn blake2b256_abc() {
    assert_eq!(
        blake2b256_of(b"abc"),
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
        "BLAKE2b-256 of 'abc' (RFC 7693)"
    );
}

/// BLAKE2b-256 output length is 32 bytes.
#[test]
fn blake2b256_output_len() {
    assert_eq!(Blake2b256.output_len(), 32);
}

/// BLAKE2b-256 buffer-too-small returns an error.
#[test]
fn blake2b256_buffer_too_small() {
    let mut out = [0u8; 16];
    let result = Blake2b256.hash(b"test", &mut out);
    assert!(
        result.is_err(),
        "short output buffer should produce an error"
    );
}

/// BLAKE2b-256 is deterministic.
#[test]
fn blake2b256_deterministic() {
    let msg = b"determinism check";
    assert_eq!(blake2b256_of(msg), blake2b256_of(msg));
}

/// BLAKE2b-256 produces different outputs for different inputs.
#[test]
fn blake2b256_different_messages() {
    assert_ne!(blake2b256_of(b"message1"), blake2b256_of(b"message2"));
}

// ── BLAKE2b-512 ──────────────────────────────────────────────────────────────

/// BLAKE2b-512("") — RFC 7693 §A.1 and Python hashlib verified.
/// hashlib.blake2b(b"", digest_size=64).hexdigest()
/// Also confirmed: `printf "" | openssl dgst -blake2b512`
#[test]
fn blake2b512_empty() {
    assert_eq!(
        blake2b512_of(b""),
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        "BLAKE2b-512 of empty string (RFC 7693 §A.1)"
    );
}

/// BLAKE2b-512("abc") — Python hashlib verified.
/// hashlib.blake2b(b"abc", digest_size=64).hexdigest()
#[test]
fn blake2b512_abc() {
    assert_eq!(
        blake2b512_of(b"abc"),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        "BLAKE2b-512 of 'abc' (RFC 7693)"
    );
}

/// BLAKE2b-512 output length is 64 bytes.
#[test]
fn blake2b512_output_len() {
    assert_eq!(Blake2b512.output_len(), 64);
}

/// BLAKE2b-512 buffer-too-small returns an error.
#[test]
fn blake2b512_buffer_too_small() {
    let mut out = [0u8; 32];
    let result = Blake2b512.hash(b"test", &mut out);
    assert!(
        result.is_err(),
        "short output buffer should produce an error"
    );
}

/// BLAKE2b-512 is deterministic.
#[test]
fn blake2b512_deterministic() {
    let msg = b"determinism check";
    assert_eq!(blake2b512_of(msg), blake2b512_of(msg));
}

// ── BLAKE2s-256 ──────────────────────────────────────────────────────────────

/// BLAKE2s-256("") — Python hashlib verified.
/// hashlib.blake2s(b"", digest_size=32).hexdigest()
#[test]
fn blake2s256_empty() {
    assert_eq!(
        blake2s256_of(b""),
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        "BLAKE2s-256 of empty string (RFC 7693)"
    );
}

/// BLAKE2s-256("abc") — Python hashlib verified and OpenSSL confirmed.
/// hashlib.blake2s(b"abc", digest_size=32).hexdigest()
/// Also confirmed: `printf "abc" | openssl dgst -blake2s256`
#[test]
fn blake2s256_abc() {
    assert_eq!(
        blake2s256_of(b"abc"),
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        "BLAKE2s-256 of 'abc' (RFC 7693)"
    );
}

/// BLAKE2s-256 output length is 32 bytes.
#[test]
fn blake2s256_output_len() {
    assert_eq!(Blake2s256.output_len(), 32);
}

/// BLAKE2s-256 buffer-too-small returns an error.
#[test]
fn blake2s256_buffer_too_small() {
    let mut out = [0u8; 16];
    let result = Blake2s256.hash(b"test", &mut out);
    assert!(
        result.is_err(),
        "short output buffer should produce an error"
    );
}

/// BLAKE2s-256 is deterministic.
#[test]
fn blake2s256_deterministic() {
    let msg = b"determinism check";
    assert_eq!(blake2s256_of(msg), blake2s256_of(msg));
}

/// BLAKE2s-256 produces different outputs for different inputs.
#[test]
fn blake2s256_different_messages() {
    assert_ne!(blake2s256_of(b"message1"), blake2s256_of(b"message2"));
}

/// BLAKE2b-256 and BLAKE2b-512 produce different-length outputs from the same input.
#[test]
fn blake2b256_and_blake2b512_differ_in_length() {
    let msg = b"length comparison";
    let mut out256 = [0u8; 32];
    let mut out512 = [0u8; 64];
    Blake2b256
        .hash(msg, &mut out256)
        .expect("blake2b-256 hash failed");
    Blake2b512
        .hash(msg, &mut out512)
        .expect("blake2b-512 hash failed");
    // The first 32 bytes differ because the IV is parameterized by output length.
    // (They are NOT a prefix relation — BLAKE2b-256 is not a truncation of BLAKE2b-512.)
    assert_ne!(
        out256.as_ref(),
        &out512[..32],
        "BLAKE2b-256 must not equal the first 32 bytes of BLAKE2b-512 (different IV)"
    );
}
