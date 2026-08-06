//! Fuzz target: `open_box` must never panic on an arbitrary "sealed box"
//! byte string (`nonce || ciphertext || tag`), regardless of length or
//! content — it must only ever return `Ok`/`Err`.
//!
//! Run with:
//!   cargo fuzz run fuzz_sealed_box_open_no_panic

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_aead::{open_box, Aes256Gcm};

fuzz_target!(|data: &[u8]| {
    // A fixed, well-formed key: this fuzz target's job is to stress the
    // untrusted `sealed` byte-string parsing (nonce/ciphertext/tag framing),
    // not key-length validation.
    let key = [0x7Au8; 32];
    let aad = b"fuzz-aad";

    let _ = open_box(&Aes256Gcm, &key, aad, data);
});
