//! Fuzz target: streaming hash output must equal one-shot hash output.
//!
//! For any input the fuzzer provides, we split it at a randomly-chosen
//! mid-point (using the first byte as a split index) and verify that feeding
//! SHA-256 and BLAKE3 in two chunks produces the same digest as one-shot.
//!
//! This catches any divergence between the streaming and one-shot code paths.
//!
//! Run with:
//!   cargo fuzz run fuzz_streaming_equivalence -- -max_len=1048576

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_core::{Hash, StreamingHash};
use oxicrypto_hash::{Blake3, Blake3Streaming, Sha256, Sha256Streaming};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use the first byte to choose a split point within the rest.
    let split_byte = data[0] as usize;
    let payload = &data[1..];
    let split = split_byte.min(payload.len());
    let (first, second) = payload.split_at(split);

    // ── SHA-256 ────────────────────────────────────────────────────────────────
    let one_shot_sha256 = {
        let mut out = [0u8; 32];
        Sha256.hash(payload, &mut out).expect("sha256 one-shot");
        out
    };

    let streaming_sha256 = {
        let mut h = Sha256Streaming::new();
        h.update(first);
        h.update(second);
        let mut out = [0u8; 32];
        h.finalize(&mut out).expect("sha256 streaming");
        out
    };

    assert_eq!(
        one_shot_sha256, streaming_sha256,
        "SHA-256 one-shot vs streaming diverged (split={split})"
    );

    // ── BLAKE3 ────────────────────────────────────────────────────────────────
    let one_shot_blake3 = {
        let mut out = [0u8; 32];
        Blake3.hash(payload, &mut out).expect("blake3 one-shot");
        out
    };

    let streaming_blake3 = {
        let mut h = Blake3Streaming::new();
        h.update(first);
        h.update(second);
        let mut out = [0u8; 32];
        h.finalize(&mut out).expect("blake3 streaming");
        out
    };

    assert_eq!(
        one_shot_blake3, streaming_blake3,
        "BLAKE3 one-shot vs streaming diverged (split={split})"
    );
});
