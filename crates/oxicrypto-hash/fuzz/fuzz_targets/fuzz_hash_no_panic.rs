//! Fuzz target: exercise all one-shot hash functions on arbitrary input.
//!
//! Goal: ensure no panics, out-of-bounds accesses, or undefined behaviour occur
//! for any input length 0–1 MiB.
//!
//! Run with:
//!   cargo fuzz run fuzz_hash_no_panic -- -max_len=1048576

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_core::Hash;
use oxicrypto_hash::{
    Blake2b256, Blake2b512, Blake2s256, Blake3, Sha256, Sha384, Sha3_256, Sha3_384, Sha3_512,
    Sha512, Sha512_256,
};

fuzz_target!(|data: &[u8]| {
    let mut out32 = [0u8; 32];
    let mut out48 = [0u8; 48];
    let mut out64 = [0u8; 64];

    // SHA-2 family
    let _ = Sha256.hash(data, &mut out32);
    let _ = Sha384.hash(data, &mut out48);
    let _ = Sha512.hash(data, &mut out64);
    let _ = Sha512_256.hash(data, &mut out32);

    // SHA-3 family
    let _ = Sha3_256.hash(data, &mut out32);
    let _ = Sha3_384.hash(data, &mut out48);
    let _ = Sha3_512.hash(data, &mut out64);

    // BLAKE2 family
    let _ = Blake2b256.hash(data, &mut out32);
    let _ = Blake2b512.hash(data, &mut out64);
    let _ = Blake2s256.hash(data, &mut out32);

    // BLAKE3
    let _ = Blake3.hash(data, &mut out32);
});
