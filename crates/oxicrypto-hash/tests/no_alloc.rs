//! Alloc-free API smoke test.
//!
//! This test exercises ONLY the allocation-free surface of `oxicrypto-hash`:
//! the inherent `hash_fixed::<N>()` methods (which write into a stack
//! `[u8; N]`) and `Hash::hash` (which writes into a caller buffer).  It must
//! pass both under the default feature set AND under `--no-default-features`:
//!
//! ```text
//! cargo test -p oxicrypto-hash --no-default-features --test no_alloc
//! ```
//!
//! Because the library compiled with `--no-default-features` links only `core`
//! (no `extern crate alloc`), a passing run proves these code paths need no
//! allocator.  (The test binary itself still uses `std` for the libtest
//! harness — what is under test is the *library's* allocation independence.)

use oxicrypto_hash::{Blake3, Sha256, Sha512};

// SHA-256("abc") — FIPS 180-4 example.
const SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

// SHA-512("abc") — FIPS 180-4 example.
const SHA512_ABC: [u8; 64] = [
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
];

// BLAKE3("abc") — official test vector (first 32 bytes of the XOF).
const BLAKE3_ABC: [u8; 32] = [
    0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
    0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
];

#[test]
fn sha256_hash_fixed_no_alloc() {
    // Inherent, stack-only path.
    assert_eq!(Sha256.hash_fixed(b"abc"), SHA256_ABC);
}

#[test]
fn sha512_hash_fixed_no_alloc() {
    assert_eq!(Sha512.hash_fixed(b"abc"), SHA512_ABC);
}

#[test]
fn blake3_hash_fixed_no_alloc() {
    assert_eq!(Blake3.hash_fixed(b"abc"), BLAKE3_ABC);
}

#[test]
fn hash_trait_into_caller_buffer_no_alloc() {
    // `Hash::hash` writes into a caller-provided buffer — no allocation, works
    // via the trait object surface too.
    use oxicrypto_hash::Hash;
    let mut out = [0u8; 32];
    Sha256.hash(b"abc", &mut out).expect("hash");
    assert_eq!(out, SHA256_ABC);
}

#[test]
fn hash_to_array_no_alloc() {
    // `Hash::hash_to_array::<N>()` from oxicrypto-core is the alloc-free
    // alternative to `hash_to_vec`.
    use oxicrypto_hash::Hash;
    let out: [u8; 32] = Sha256.hash_to_array(b"abc").expect("hash_to_array");
    assert_eq!(out, SHA256_ABC);
}
