//! Streaming vs one-shot equivalence tests.
//!
//! For each hash algorithm, verify that feeding the same message in any
//! possible split produces an identical digest to the one-shot API.
//! This exhaustively checks message splits for short messages.

use oxicrypto_core::{Hash, StreamingHash};
use oxicrypto_hash::{
    Blake2b256, Blake2b256Streaming, Blake2b512, Blake2b512Streaming, Blake2s256,
    Blake2s256Streaming, Blake3, Blake3Streaming, Sha256, Sha256Streaming, Sha384, Sha384Streaming,
    Sha512, Sha512Streaming,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn sha256_oneshot(msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Sha256.hash(msg, &mut out).expect("sha256 one-shot failed");
    out
}

fn sha384_oneshot(msg: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    Sha384.hash(msg, &mut out).expect("sha384 one-shot failed");
    out
}

fn sha512_oneshot(msg: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    Sha512.hash(msg, &mut out).expect("sha512 one-shot failed");
    out
}

fn blake3_oneshot(msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Blake3.hash(msg, &mut out).expect("blake3 one-shot failed");
    out
}

fn blake2b256_oneshot(msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Blake2b256
        .hash(msg, &mut out)
        .expect("blake2b-256 one-shot failed");
    out
}

fn blake2b512_oneshot(msg: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    Blake2b512
        .hash(msg, &mut out)
        .expect("blake2b-512 one-shot failed");
    out
}

fn blake2s256_oneshot(msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Blake2s256
        .hash(msg, &mut out)
        .expect("blake2s-256 one-shot failed");
    out
}

// ── SHA-256 streaming equivalence ─────────────────────────────────────────────

fn check_sha256_all_splits(msg: &[u8]) {
    let expected = sha256_oneshot(msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut streamer = Sha256Streaming::new();
        StreamingHash::update(&mut streamer, a);
        StreamingHash::update(&mut streamer, b);
        let mut got = [0u8; 32];
        StreamingHash::finalize(streamer, &mut got).expect("sha256 streaming finalize failed");
        assert_eq!(
            expected, got,
            "SHA-256 streaming split at byte {} failed for msg {:?}",
            split, msg
        );
    }
}

#[test]
fn sha256_streaming_all_splits_empty() {
    check_sha256_all_splits(b"");
}

#[test]
fn sha256_streaming_all_splits_hello() {
    check_sha256_all_splits(b"Hello");
}

#[test]
fn sha256_streaming_all_splits_quick_brown_fox() {
    check_sha256_all_splits(b"The quick brown fox jumps over the lazy dog");
}

#[test]
fn sha256_streaming_all_splits_448bit_message() {
    check_sha256_all_splits(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
}

// ── SHA-384 streaming equivalence ─────────────────────────────────────────────

fn check_sha384_all_splits(msg: &[u8]) {
    let expected = sha384_oneshot(msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut streamer = Sha384Streaming::new();
        StreamingHash::update(&mut streamer, a);
        StreamingHash::update(&mut streamer, b);
        let mut got = [0u8; 48];
        StreamingHash::finalize(streamer, &mut got).expect("sha384 streaming finalize failed");
        assert_eq!(
            expected, got,
            "SHA-384 streaming split at byte {} failed for msg {:?}",
            split, msg
        );
    }
}

#[test]
fn sha384_streaming_all_splits_empty() {
    check_sha384_all_splits(b"");
}

#[test]
fn sha384_streaming_all_splits_hello() {
    check_sha384_all_splits(b"Hello");
}

#[test]
fn sha384_streaming_all_splits_quick_brown_fox() {
    check_sha384_all_splits(b"The quick brown fox jumps over the lazy dog");
}

// ── SHA-512 streaming equivalence ─────────────────────────────────────────────

fn check_sha512_all_splits(msg: &[u8]) {
    let expected = sha512_oneshot(msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut streamer = Sha512Streaming::new();
        StreamingHash::update(&mut streamer, a);
        StreamingHash::update(&mut streamer, b);
        let mut got = [0u8; 64];
        StreamingHash::finalize(streamer, &mut got).expect("sha512 streaming finalize failed");
        assert_eq!(
            expected, got,
            "SHA-512 streaming split at byte {} failed for msg {:?}",
            split, msg
        );
    }
}

#[test]
fn sha512_streaming_all_splits_empty() {
    check_sha512_all_splits(b"");
}

#[test]
fn sha512_streaming_all_splits_hello() {
    check_sha512_all_splits(b"Hello");
}

#[test]
fn sha512_streaming_all_splits_quick_brown_fox() {
    check_sha512_all_splits(b"The quick brown fox jumps over the lazy dog");
}

// ── BLAKE3 streaming equivalence ─────────────────────────────────────────────

fn check_blake3_all_splits(msg: &[u8]) {
    let expected = blake3_oneshot(msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut streamer = Blake3Streaming::new();
        StreamingHash::update(&mut streamer, a);
        StreamingHash::update(&mut streamer, b);
        let mut got = [0u8; 32];
        StreamingHash::finalize(streamer, &mut got).expect("blake3 streaming finalize failed");
        assert_eq!(
            expected, got,
            "BLAKE3 streaming split at byte {} failed for msg {:?}",
            split, msg
        );
    }
}

#[test]
fn blake3_streaming_all_splits_empty() {
    check_blake3_all_splits(b"");
}

#[test]
fn blake3_streaming_all_splits_hello() {
    check_blake3_all_splits(b"Hello");
}

#[test]
fn blake3_streaming_all_splits_quick_brown_fox() {
    check_blake3_all_splits(b"The quick brown fox jumps over the lazy dog");
}

// ── BLAKE2b-256 streaming equivalence ─────────────────────────────────────────

fn check_blake2b256_all_splits(msg: &[u8]) {
    let expected = blake2b256_oneshot(msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut streamer = Blake2b256Streaming::new();
        StreamingHash::update(&mut streamer, a);
        StreamingHash::update(&mut streamer, b);
        let mut got = [0u8; 32];
        StreamingHash::finalize(streamer, &mut got).expect("blake2b-256 streaming finalize failed");
        assert_eq!(
            expected, got,
            "BLAKE2b-256 streaming split at byte {} failed for msg {:?}",
            split, msg
        );
    }
}

#[test]
fn blake2b256_streaming_all_splits_empty() {
    check_blake2b256_all_splits(b"");
}

#[test]
fn blake2b256_streaming_all_splits_hello() {
    check_blake2b256_all_splits(b"Hello");
}

#[test]
fn blake2b256_streaming_all_splits_quick_brown_fox() {
    check_blake2b256_all_splits(b"The quick brown fox jumps over the lazy dog");
}

// ── BLAKE2b-512 streaming equivalence ─────────────────────────────────────────

fn check_blake2b512_all_splits(msg: &[u8]) {
    let expected = blake2b512_oneshot(msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut streamer = Blake2b512Streaming::new();
        StreamingHash::update(&mut streamer, a);
        StreamingHash::update(&mut streamer, b);
        let mut got = [0u8; 64];
        StreamingHash::finalize(streamer, &mut got).expect("blake2b-512 streaming finalize failed");
        assert_eq!(
            expected, got,
            "BLAKE2b-512 streaming split at byte {} failed for msg {:?}",
            split, msg
        );
    }
}

#[test]
fn blake2b512_streaming_all_splits_empty() {
    check_blake2b512_all_splits(b"");
}

#[test]
fn blake2b512_streaming_all_splits_hello() {
    check_blake2b512_all_splits(b"Hello");
}

#[test]
fn blake2b512_streaming_all_splits_quick_brown_fox() {
    check_blake2b512_all_splits(b"The quick brown fox jumps over the lazy dog");
}

// ── BLAKE2s-256 streaming equivalence ─────────────────────────────────────────

fn check_blake2s256_all_splits(msg: &[u8]) {
    let expected = blake2s256_oneshot(msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut streamer = Blake2s256Streaming::new();
        StreamingHash::update(&mut streamer, a);
        StreamingHash::update(&mut streamer, b);
        let mut got = [0u8; 32];
        StreamingHash::finalize(streamer, &mut got).expect("blake2s-256 streaming finalize failed");
        assert_eq!(
            expected, got,
            "BLAKE2s-256 streaming split at byte {} failed for msg {:?}",
            split, msg
        );
    }
}

#[test]
fn blake2s256_streaming_all_splits_empty() {
    check_blake2s256_all_splits(b"");
}

#[test]
fn blake2s256_streaming_all_splits_hello() {
    check_blake2s256_all_splits(b"Hello");
}

#[test]
fn blake2s256_streaming_all_splits_quick_brown_fox() {
    check_blake2s256_all_splits(b"The quick brown fox jumps over the lazy dog");
}
