//! Fuzz target: HMAC truncated MAC / verify must never panic on an
//! attacker-controlled length, in either direction:
//!
//! - `mac_truncated(key, msg, out)`: `out.len()` is arbitrary (write side).
//! - `verify_truncated(key, msg, tag)` / `hmac_sha256_verify_truncated`:
//!   `tag.len()` is arbitrary (read side).
//!
//! This is a regression guard for a previously-fixed bug class: `verify_truncated`
//! and `mac_truncated` on `HmacSha256`/`HmacSha384`/`HmacSha512` used to slice
//! a fixed-size digest buffer (`buf[..n]` / `full[..n]`) with an attacker-supplied
//! `n` and no upper bound, causing an out-of-bounds-slice panic whenever the
//! caller-supplied length exceeded the digest length. Both are now bound to an
//! inclusive `16..=digest_len` and return `CryptoError::BadInput` outside that
//! range (see `crates/oxicrypto-mac/src/lib.rs`).
//!
//! Run with:
//!   cargo fuzz run fuzz_hmac_truncated_no_panic

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_mac::{hmac_sha256_verify_truncated, HmacSha256, HmacSha384, HmacSha512};

const KEY: &[u8] = b"fuzz-hmac-truncated-key";
const MSG: &[u8] = b"fuzz-hmac-truncated-message";

fuzz_target!(|data: &[u8]| {
    // ── Read side: arbitrary-length tag passed to verify_truncated ──────────
    let _ = HmacSha256.verify_truncated(KEY, MSG, data);
    let _ = HmacSha384.verify_truncated(KEY, MSG, data);
    let _ = HmacSha512.verify_truncated(KEY, MSG, data);
    let _ = hmac_sha256_verify_truncated(KEY, MSG, data);

    // ── Write side: arbitrary-length `out` buffer passed to mac_truncated ───
    // Capped to keep allocation bounded regardless of libfuzzer's -max_len;
    // the interesting range (0..=70) comfortably covers every digest length
    // (32/48/64) and its surrounding boundary values.
    let out_len = data.len() % 256;
    let mut out = vec![0u8; out_len];
    let _ = HmacSha256.mac_truncated(KEY, MSG, &mut out);
    let _ = HmacSha384.mac_truncated(KEY, MSG, &mut out);
    let _ = HmacSha512.mac_truncated(KEY, MSG, &mut out);
});
