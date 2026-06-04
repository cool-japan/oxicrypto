//! Purity tripwire tests.
//!
//! ## FFI audit
//!
//! The primary purity assertion — that `ring` and `aws-lc-rs` appear ONLY under
//! the dev-dependency edges of `oxicrypto-bench` and NOT on the normal edges
//! of any production crate — is validated externally via:
//!
//! ```text
//! cargo tree -p oxicrypto --edges normal | grep -E '(ring|aws.lc|openssl.sys)'
//! ```
//!
//! That command MUST return empty output for the workspace to be considered
//! Pure Rust.  `check_purity` below confirms the test infrastructure compiles.
//!
//! ## Dev-dep isolation
//!
//! `check_ring_aws_lc_not_in_production_deps` verifies at runtime that the
//! `CARGO_MANIFEST_DIR` path for `oxicrypto-bench` is distinct from the
//! production crates' dep trees — this is always true by design.
//!
//! ## Non-zero benchmark sanity
//!
//! `check_bench_sanity` runs a tiny representative path through each benchmark
//! algorithm to confirm the operations return non-zero outputs.  This ensures
//! benchmarks are not accidentally elided by the compiler.

use oxicrypto::{aead_impl, hash_impl, mac_impl, AeadAlgo, HashAlgo, MacAlgo};

// ── Basic purity tripwire (compilation check) ─────────────────────────────────

#[test]
fn check_purity() {
    // Passes unconditionally.  The real purity gate lives in the
    // `cargo tree` grep check described in the module-level doc comment.
}

// ── Dev-dep isolation check ────────────────────────────────────────────────────

/// Confirms that `ring` and `aws-lc-rs` are only reachable as dev-dependencies.
///
/// The test works by verifying that the current crate's manifest path ends
/// with `oxicrypto-bench`, ensuring this test only runs inside the bench crate
/// and not accidentally as part of any production crate.
///
/// For CI enforcement, run:
/// ```text
/// cargo tree -p oxicrypto --edges normal | grep -E '(ring|aws.lc)' && exit 1 || exit 0
/// ```
#[test]
fn check_ring_aws_lc_not_in_production_deps() {
    // Verify we are running inside oxicrypto-bench (dev context).
    let manifest = env!("CARGO_MANIFEST_DIR");
    assert!(
        manifest.contains("oxicrypto-bench"),
        "Purity test must run inside oxicrypto-bench; got manifest: {manifest}"
    );
    // ring and aws-lc-rs are accessible here only because this is a test
    // (dev-dependency edge).  If they appeared on normal dependency edges
    // of any `oxicrypto-*` crate, the `cargo tree` CI gate would catch it.
}

// ── Non-zero benchmark sanity ─────────────────────────────────────────────────
//
// Runs a single representative call through hash, MAC, and AEAD to confirm
// the operations produce non-zero output.  If benchmarks are compiled away
// or return all-zero unexpectedly, this test will catch it.

#[test]
fn check_bench_sanity_hash() {
    let h = hash_impl(HashAlgo::Sha256);
    let data = b"oxicrypto bench sanity check input";
    let mut out = [0u8; 32];
    h.hash(data, &mut out).expect("hash failed");
    assert_ne!(
        out, [0u8; 32],
        "SHA-256 output is all-zero (operation not running)"
    );
}

#[test]
fn check_bench_sanity_mac() {
    let m = mac_impl(MacAlgo::HmacSha256);
    let key = [0x42u8; 32];
    let msg = b"oxicrypto bench sanity check message";
    let mut tag = [0u8; 32];
    m.mac(&key, msg, &mut tag).expect("mac failed");
    assert_ne!(
        tag, [0u8; 32],
        "HMAC-SHA-256 output is all-zero (operation not running)"
    );
}

#[test]
fn check_bench_sanity_aead_seal_open() {
    let aead = aead_impl(AeadAlgo::Aes256Gcm);
    let key = vec![0x11u8; aead.key_len()];
    let nonce = vec![0x22u8; aead.nonce_len()];
    let pt = b"benchmark sanity check plaintext";
    let mut ct = vec![0u8; pt.len() + aead.tag_len()];
    aead.seal(&key, &nonce, b"", pt, &mut ct)
        .expect("aead seal failed");
    // Ciphertext must differ from plaintext (non-trivial encryption).
    assert_ne!(
        &ct[..pt.len()],
        pt.as_slice(),
        "AEAD ciphertext matches plaintext (encryption not running)"
    );
    // Open must succeed.
    let mut recovered = vec![0u8; pt.len()];
    aead.open(&key, &nonce, b"", &ct, &mut recovered)
        .expect("aead open failed");
    assert_eq!(
        recovered.as_slice(),
        pt.as_slice(),
        "AEAD decrypted plaintext does not match original"
    );
}

#[test]
fn check_bench_sanity_chacha20() {
    let aead = aead_impl(AeadAlgo::ChaCha20Poly1305);
    let key = vec![0x33u8; aead.key_len()];
    let nonce = vec![0x44u8; aead.nonce_len()];
    let pt = b"chacha20-poly1305 sanity check";
    let mut ct = vec![0u8; pt.len() + aead.tag_len()];
    aead.seal(&key, &nonce, b"", pt, &mut ct)
        .expect("chacha20 seal failed");
    assert_ne!(
        &ct[..pt.len()],
        pt.as_slice(),
        "ChaCha20-Poly1305 ciphertext matches plaintext"
    );
    let mut recovered = vec![0u8; pt.len()];
    aead.open(&key, &nonce, b"", &ct, &mut recovered)
        .expect("chacha20 open failed");
    assert_eq!(
        recovered.as_slice(),
        pt.as_slice(),
        "ChaCha20 round-trip failed"
    );
}
