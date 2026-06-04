//! Fuzz target: exercise XOF functions (SHAKE128/256, cSHAKE, TupleHash, BLAKE3 XOF).
//!
//! Goal: ensure no panics on arbitrary message lengths and output sizes.
//!
//! Run with:
//!   cargo fuzz run fuzz_xof_no_panic -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_hash::{
    blake3_xof, cshake128, cshake256, shake128, shake256, tuple_hash128, tuple_hash256,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Use first 2 bytes to determine output length (1–256 bytes).
    let out_len = ((u16::from_le_bytes([data[0], data[1]]) as usize) % 256) + 1;
    let msg = &data[2..];

    // ── SHAKE128 / SHAKE256 ────────────────────────────────────────────────────
    let mut shake_out = vec![0u8; out_len];
    shake128(msg, &mut shake_out);
    shake256(msg, &mut shake_out);

    // ── cSHAKE128 / cSHAKE256 ─────────────────────────────────────────────────
    // Use fixed customization strings for simplicity.
    cshake128(msg, b"fuzz", b"fuzz-custom", &mut shake_out);
    cshake256(msg, b"fuzz", b"fuzz-custom", &mut shake_out);

    // ── TupleHash128 / TupleHash256 ───────────────────────────────────────────
    // Split msg into two parts for a two-element tuple.
    let mid = msg.len() / 2;
    let (a, b) = msg.split_at(mid);
    let _ = tuple_hash128(&[a, b], b"", &mut shake_out);
    let _ = tuple_hash256(&[a, b], b"", &mut shake_out);

    // ── BLAKE3 XOF ────────────────────────────────────────────────────────────
    let _xof = blake3_xof(msg, out_len);
});
