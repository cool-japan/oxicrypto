//! Large-input sanity tests for hash functions.
//!
//! These tests verify that hash functions handle 1 MiB inputs without
//! panicking and produce non-trivial (non-zero) output. They do not check
//! against a known digest value (which would require recomputing offline)
//! but confirm both correctness invariants:
//!   1. The output is non-zero.
//!   2. The streaming and one-shot APIs agree for large inputs.

use oxicrypto_core::{Hash, StreamingHash};
use oxicrypto_hash::{
    Blake3, Blake3Streaming, Sha256, Sha256Streaming, Sha384, Sha384Streaming, Sha512,
    Sha512Streaming,
};

const MIB: usize = 1024 * 1024;
const FILL_BYTE: u8 = 0x42;

#[test]
fn sha256_1mib_nonzero() {
    let data = vec![FILL_BYTE; MIB];
    let mut out = [0u8; 32];
    Sha256
        .hash(&data, &mut out)
        .expect("sha256 1MiB hash failed");
    assert_ne!(out, [0u8; 32], "SHA-256 of 1 MiB must be non-zero");
}

#[test]
fn sha256_1mib_streaming_matches_oneshot() {
    let data = vec![FILL_BYTE; MIB];

    let mut oneshot_out = [0u8; 32];
    Sha256
        .hash(&data, &mut oneshot_out)
        .expect("sha256 one-shot failed");

    // Feed as two 512 KiB chunks
    let half = MIB / 2;
    let mut streamer = Sha256Streaming::new();
    StreamingHash::update(&mut streamer, &data[..half]);
    StreamingHash::update(&mut streamer, &data[half..]);
    let mut stream_out = [0u8; 32];
    StreamingHash::finalize(streamer, &mut stream_out).expect("sha256 streaming finalize failed");

    assert_eq!(
        oneshot_out, stream_out,
        "SHA-256: streaming and one-shot must agree for 1 MiB input"
    );
}

#[test]
fn sha384_1mib_nonzero() {
    let data = vec![FILL_BYTE; MIB];
    let mut out = [0u8; 48];
    Sha384
        .hash(&data, &mut out)
        .expect("sha384 1MiB hash failed");
    assert_ne!(out, [0u8; 48], "SHA-384 of 1 MiB must be non-zero");
}

#[test]
fn sha384_1mib_streaming_matches_oneshot() {
    let data = vec![FILL_BYTE; MIB];

    let mut oneshot_out = [0u8; 48];
    Sha384
        .hash(&data, &mut oneshot_out)
        .expect("sha384 one-shot failed");

    let half = MIB / 2;
    let mut streamer = Sha384Streaming::new();
    StreamingHash::update(&mut streamer, &data[..half]);
    StreamingHash::update(&mut streamer, &data[half..]);
    let mut stream_out = [0u8; 48];
    StreamingHash::finalize(streamer, &mut stream_out).expect("sha384 streaming finalize failed");

    assert_eq!(
        oneshot_out, stream_out,
        "SHA-384: streaming and one-shot must agree for 1 MiB input"
    );
}

#[test]
fn sha512_1mib_nonzero() {
    let data = vec![FILL_BYTE; MIB];
    let mut out = [0u8; 64];
    Sha512
        .hash(&data, &mut out)
        .expect("sha512 1MiB hash failed");
    assert_ne!(out, [0u8; 64], "SHA-512 of 1 MiB must be non-zero");
}

#[test]
fn sha512_1mib_streaming_matches_oneshot() {
    let data = vec![FILL_BYTE; MIB];

    let mut oneshot_out = [0u8; 64];
    Sha512
        .hash(&data, &mut oneshot_out)
        .expect("sha512 one-shot failed");

    let half = MIB / 2;
    let mut streamer = Sha512Streaming::new();
    StreamingHash::update(&mut streamer, &data[..half]);
    StreamingHash::update(&mut streamer, &data[half..]);
    let mut stream_out = [0u8; 64];
    StreamingHash::finalize(streamer, &mut stream_out).expect("sha512 streaming finalize failed");

    assert_eq!(
        oneshot_out, stream_out,
        "SHA-512: streaming and one-shot must agree for 1 MiB input"
    );
}

#[test]
fn blake3_1mib_nonzero() {
    let data = vec![FILL_BYTE; MIB];
    let mut out = [0u8; 32];
    Blake3
        .hash(&data, &mut out)
        .expect("blake3 1MiB hash failed");
    assert_ne!(out, [0u8; 32], "BLAKE3 of 1 MiB must be non-zero");
}

#[test]
fn blake3_1mib_streaming_matches_oneshot() {
    let data = vec![FILL_BYTE; MIB];

    let mut oneshot_out = [0u8; 32];
    Blake3
        .hash(&data, &mut oneshot_out)
        .expect("blake3 one-shot failed");

    let half = MIB / 2;
    let mut streamer = Blake3Streaming::new();
    StreamingHash::update(&mut streamer, &data[..half]);
    StreamingHash::update(&mut streamer, &data[half..]);
    let mut stream_out = [0u8; 32];
    StreamingHash::finalize(streamer, &mut stream_out).expect("blake3 streaming finalize failed");

    assert_eq!(
        oneshot_out, stream_out,
        "BLAKE3: streaming and one-shot must agree for 1 MiB input"
    );
}
