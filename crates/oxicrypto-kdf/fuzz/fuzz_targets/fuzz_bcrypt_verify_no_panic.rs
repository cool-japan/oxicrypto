//! Fuzz target: `bcrypt_verify` must never panic on an arbitrary,
//! attacker-influenced hash string — including strings that are valid UTF-8
//! but contain multi-byte characters landing on the byte offsets the parser
//! slices at (a real bug found here previously: `hash_part[..22]` on a `str`
//! panics with "byte index N is not a char boundary" when byte 22 falls
//! inside a multi-byte sequence; see `ensure_ascii_hash` in
//! `bcrypt_kdf.rs`, which now rejects non-ASCII input up front).
//!
//! `data` is reinterpreted as UTF-8 when valid (the exact condition under
//! which `str` slicing panics on a non-boundary index), and as a lossy
//! string otherwise, so both "plausible attacker string" and "raw byte
//! garbage decoded as text upstream" input classes are covered.
//!
//! Run with:
//!   cargo fuzz run fuzz_bcrypt_verify_no_panic

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_kdf::bcrypt_verify;

fuzz_target!(|data: &[u8]| {
    // Exact bytes, only when they happen to be valid UTF-8 (`&str` requires
    // this at the type level; this is the primary fuzz surface for the
    // char-boundary-panic bug class).
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = bcrypt_verify(b"probe-password", s);
    }

    // Lossy conversion additionally exercises replacement-character-laden
    // strings (U+FFFD is itself a 3-byte UTF-8 sequence, so this still
    // stresses char-boundary arithmetic even for inputs that were not
    // originally valid UTF-8).
    let lossy = String::from_utf8_lossy(data);
    let _ = bcrypt_verify(b"probe-password", &lossy);
});
