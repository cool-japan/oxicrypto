//! Fuzz target: RFC 3394 AES key unwrap (`aes128_key_unwrap` /
//! `aes256_key_unwrap`) must never panic on arbitrary `wrapped` bytes,
//! regardless of length or content.
//!
//! `out` is sized to `data.len()`, which always over-approximates the true
//! unwrapped length (unwrap output is always 8 bytes shorter than the
//! wrapped input), so a length mismatch surfaces as `Err`, never an
//! out-of-bounds write.
//!
//! Run with:
//!   cargo fuzz run fuzz_key_unwrap_no_panic

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_aead::{aes128_key_unwrap, aes256_key_unwrap};

fuzz_target!(|data: &[u8]| {
    let kek128 = [0x11u8; 16];
    let kek256 = [0x22u8; 32];
    let mut out = vec![0u8; data.len()];

    let _ = aes128_key_unwrap(&kek128, data, &mut out);
    let _ = aes256_key_unwrap(&kek256, data, &mut out);
});
