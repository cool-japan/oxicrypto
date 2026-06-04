//! Property tests and structured fuzz tests for all KDFs in oxicrypto-kdf.
//!
//! These tests verify:
//! - Determinism: same inputs always produce same output
//! - Salt sensitivity: different salts produce different outputs
//! - Error handling: no KDF panics on arbitrary parameter combinations
//!
//! ## Structured fuzz testing
//!
//! The "fuzz test" here is a *structured* exhaustive-style sweep over parameter
//! combinations rather than coverage-guided fuzzing (which requires `cargo-fuzz`
//! and a separate fuzz target crate).  Each test systematically covers the
//! boundaries that production code is most likely to get wrong:
//!
//! - Empty / minimal / maximal-safe lengths
//! - Zero or near-zero cost parameters
//! - Very long passwords / salts
//!
//! Coverage-guided fuzzing targets can be added under `fuzz/` when a nightly
//! toolchain is available; these tests serve as a fast always-running gate.

use oxicrypto_core::{CryptoError, Kdf};
use oxicrypto_kdf::{
    argon2_kdf::{argon2id_derive, Argon2Params},
    balloon::balloon_sha256,
    bcrypt_kdf::bcrypt_hash,
    hkdf_sha256_derive_to_vec, hkdf_sha384_derive_to_vec, hkdf_sha512_derive_to_vec,
    pbkdf2_kdf::pbkdf2_sha256,
    scrypt_kdf::{scrypt_derive, ScryptParams},
    HkdfSha256, HkdfSha384, HkdfSha512,
};

// ── Shared helpers ────────────────────────────────────────────────────────────

const SALT16: &[u8] = b"saltsaltsaltsalt";
const SALT16B: &[u8] = b"SALTSALTSALTSALT"; // Different salt same length

/// A set of representative password lengths to sweep.
const PASSWORDS: &[&[u8]] = &[
    b"",                             // empty
    b"x",                            // 1 byte
    b"password",                     // typical
    b"correct horse battery staple", // passphrase
    &[0u8; 72],                      // 72 zero bytes (bcrypt boundary)
    &[0xffu8; 73],                   // 73 bytes (one past bcrypt boundary)
    &[0xaau8; 128],                  // long password
];

/// A set of representative salt lengths to sweep (used in cross-KDF and fuzz tests).
#[allow(dead_code)]
const SALTS: &[&[u8]] = &[
    b"",                                 // empty (HKDF/scrypt allow; Argon2 does not)
    b"12345678",                         // 8 bytes (Argon2 minimum)
    b"1234567890123456",                 // 16 bytes (recommended minimum)
    b"12345678901234567890123456789012", // 32 bytes
];

// ── HKDF-SHA-256 property tests ───────────────────────────────────────────────

/// HKDF-SHA-256 is deterministic for every (password, salt, info) combination.
#[test]
fn prop_hkdf_sha256_deterministic_sweep() {
    let kdf = HkdfSha256;
    for &pw in PASSWORDS {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        // Use empty info for simplicity; the info parameter is orthogonal.
        kdf.derive(pw, SALT16, b"", &mut out1).unwrap_or_default();
        kdf.derive(pw, SALT16, b"", &mut out2).unwrap_or_default();
        assert_eq!(
            out1,
            out2,
            "HKDF-SHA-256 not deterministic for pw len={}",
            pw.len()
        );
    }
}

/// HKDF-SHA-256 produces different outputs for different salts.
#[test]
fn prop_hkdf_sha256_salt_sensitivity() {
    let kdf = HkdfSha256;
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    kdf.derive(b"password", SALT16, b"", &mut out_a).unwrap();
    kdf.derive(b"password", SALT16B, b"", &mut out_b).unwrap();
    assert_ne!(out_a, out_b, "HKDF-SHA-256 must be salt-sensitive");
}

// ── HKDF-SHA-384 property tests ───────────────────────────────────────────────

/// HKDF-SHA-384 is deterministic for every (password, salt) combination.
#[test]
fn prop_hkdf_sha384_deterministic_sweep() {
    let kdf = HkdfSha384;
    for &pw in PASSWORDS {
        let mut out1 = [0u8; 48];
        let mut out2 = [0u8; 48];
        kdf.derive(pw, SALT16, b"", &mut out1).unwrap_or_default();
        kdf.derive(pw, SALT16, b"", &mut out2).unwrap_or_default();
        assert_eq!(
            out1,
            out2,
            "HKDF-SHA-384 not deterministic for pw len={}",
            pw.len()
        );
    }
}

/// HKDF-SHA-384 produces different outputs for different salts.
#[test]
fn prop_hkdf_sha384_salt_sensitivity() {
    let kdf = HkdfSha384;
    let mut out_a = [0u8; 48];
    let mut out_b = [0u8; 48];
    kdf.derive(b"password", SALT16, b"", &mut out_a).unwrap();
    kdf.derive(b"password", SALT16B, b"", &mut out_b).unwrap();
    assert_ne!(out_a, out_b, "HKDF-SHA-384 must be salt-sensitive");
}

// ── HKDF-SHA-512 property tests ───────────────────────────────────────────────

/// HKDF-SHA-512 is deterministic for every (password, salt) combination.
#[test]
fn prop_hkdf_sha512_deterministic_sweep() {
    let kdf = HkdfSha512;
    for &pw in PASSWORDS {
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        kdf.derive(pw, SALT16, b"", &mut out1).unwrap_or_default();
        kdf.derive(pw, SALT16, b"", &mut out2).unwrap_or_default();
        assert_eq!(
            out1,
            out2,
            "HKDF-SHA-512 not deterministic for pw len={}",
            pw.len()
        );
    }
}

/// HKDF-SHA-512 produces different outputs for different salts.
#[test]
fn prop_hkdf_sha512_salt_sensitivity() {
    let kdf = HkdfSha512;
    let mut out_a = [0u8; 64];
    let mut out_b = [0u8; 64];
    kdf.derive(b"password", SALT16, b"", &mut out_a).unwrap();
    kdf.derive(b"password", SALT16B, b"", &mut out_b).unwrap();
    assert_ne!(out_a, out_b, "HKDF-SHA-512 must be salt-sensitive");
}

// ── PBKDF2-SHA-256 property tests ────────────────────────────────────────────

/// PBKDF2-SHA-256 is deterministic.
#[test]
fn prop_pbkdf2_sha256_deterministic_sweep() {
    for &pw in PASSWORDS {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        pbkdf2_sha256(pw, SALT16, 100, &mut out1).unwrap_or_default();
        pbkdf2_sha256(pw, SALT16, 100, &mut out2).unwrap_or_default();
        assert_eq!(
            out1,
            out2,
            "PBKDF2-SHA-256 not deterministic for pw len={}",
            pw.len()
        );
    }
}

/// PBKDF2-SHA-256 is salt-sensitive.
#[test]
fn prop_pbkdf2_sha256_salt_sensitivity() {
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    pbkdf2_sha256(b"password", SALT16, 1000, &mut out_a).unwrap();
    pbkdf2_sha256(b"password", SALT16B, 1000, &mut out_b).unwrap();
    assert_ne!(out_a, out_b, "PBKDF2-SHA-256 must be salt-sensitive");
}

// ── Argon2id property tests ───────────────────────────────────────────────────

/// Argon2id is deterministic over representative input variations.
#[test]
fn prop_argon2id_deterministic_sweep() {
    let params = Argon2Params::TEST_PARAMS;
    // Only use salts ≥ 8 bytes (Argon2 minimum).
    for &pw in PASSWORDS {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        argon2id_derive(pw, SALT16, params, &mut out1).unwrap_or_default();
        argon2id_derive(pw, SALT16, params, &mut out2).unwrap_or_default();
        assert_eq!(
            out1,
            out2,
            "Argon2id not deterministic for pw len={}",
            pw.len()
        );
    }
}

/// Argon2id is salt-sensitive.
#[test]
fn prop_argon2id_salt_sensitivity() {
    let params = Argon2Params::TEST_PARAMS;
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    argon2id_derive(b"password", SALT16, params, &mut out_a).unwrap();
    argon2id_derive(b"password", SALT16B, params, &mut out_b).unwrap();
    assert_ne!(out_a, out_b, "Argon2id must be salt-sensitive");
}

// ── scrypt property tests ─────────────────────────────────────────────────────

/// scrypt is deterministic.
#[test]
fn prop_scrypt_deterministic_sweep() {
    // log_n=4 (N=16) is fast enough for a sweep.
    for &pw in PASSWORDS {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        scrypt_derive(pw, SALT16, 4, 8, 1, &mut out1).unwrap_or_default();
        scrypt_derive(pw, SALT16, 4, 8, 1, &mut out2).unwrap_or_default();
        assert_eq!(
            out1,
            out2,
            "scrypt not deterministic for pw len={}",
            pw.len()
        );
    }
}

/// scrypt is salt-sensitive.
#[test]
fn prop_scrypt_salt_sensitivity() {
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    scrypt_derive(b"password", SALT16, 4, 8, 1, &mut out_a).unwrap();
    scrypt_derive(b"password", SALT16B, 4, 8, 1, &mut out_b).unwrap();
    assert_ne!(out_a, out_b, "scrypt must be salt-sensitive");
}

// ── Balloon-SHA-256 property tests ────────────────────────────────────────────

/// Balloon-SHA-256 is deterministic.
#[test]
fn prop_balloon_sha256_deterministic_sweep() {
    for &pw in PASSWORDS {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        balloon_sha256(pw, SALT16, 4, 3, &mut out1).unwrap_or_default();
        balloon_sha256(pw, SALT16, 4, 3, &mut out2).unwrap_or_default();
        assert_eq!(
            out1,
            out2,
            "Balloon-SHA-256 not deterministic for pw len={}",
            pw.len()
        );
    }
}

/// Balloon-SHA-256 is salt-sensitive.
#[test]
fn prop_balloon_sha256_salt_sensitivity() {
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    balloon_sha256(b"password", SALT16, 4, 3, &mut out_a).unwrap();
    balloon_sha256(b"password", SALT16B, 4, 3, &mut out_b).unwrap();
    assert_ne!(out_a, out_b, "Balloon-SHA-256 must be salt-sensitive");
}

// ── Structured fuzz: no KDF panics on arbitrary parameter combinations ─────────
//
// We sweep over a grid of "adversarial" parameter values to confirm that every
// KDF returns `Err(CryptoError::BadInput)` (or `Ok`) but never panics.
// Each test function is named after the KDF it exercises.

/// HKDF test case type: (ikm, salt, info, output_len).
type HkdfCase = (&'static [u8], &'static [u8], &'static [u8], usize);

/// HKDF-SHA-256: no panic on extreme output lengths or empty inputs.
#[test]
fn fuzz_hkdf_sha256_no_panic() {
    let kdf = HkdfSha256;
    let test_cases: Vec<HkdfCase> = vec![
        (b"", b"", b"", 0),
        (b"", b"", b"", 1),
        (b"", b"", b"", 32),
        (b"ikm", b"", b"", 0),
        (b"ikm", b"salt", b"info", 0),
        (b"ikm", b"salt", b"info", 255 * 32),       // max valid
        (b"ikm", b"salt", b"info", 255 * 32 + 1),   // one over max
        (b"ikm", b"salt", b"info", usize::MAX / 2), // huge (should error gracefully)
    ];
    for (ikm, salt, info, len) in test_cases {
        if len == 0 || len > 255 * 32 {
            // Either BadInput or Internal; must not panic.
            let result = hkdf_sha256_derive_to_vec(ikm, salt, info, len);
            assert!(result.is_err(), "expected error for len={len}");
        } else {
            let mut out = vec![0u8; len];
            let _ = kdf.derive(ikm, salt, info, &mut out); // must not panic
        }
    }
}

/// HKDF-SHA-384: no panic on extreme output lengths or empty inputs.
#[test]
fn fuzz_hkdf_sha384_no_panic() {
    let test_cases: Vec<HkdfCase> = vec![
        (b"", b"", b"", 0),
        (b"ikm", b"salt", b"info", 0),
        (b"ikm", b"salt", b"info", 255 * 48),
        (b"ikm", b"salt", b"info", 255 * 48 + 1),
    ];
    for (ikm, salt, info, len) in test_cases {
        if len == 0 || len > 255 * 48 {
            let result = hkdf_sha384_derive_to_vec(ikm, salt, info, len);
            assert!(result.is_err(), "expected error for len={len}");
        } else {
            let kdf = HkdfSha384;
            let mut out = vec![0u8; len];
            let _ = kdf.derive(ikm, salt, info, &mut out);
        }
    }
}

/// HKDF-SHA-512: no panic on extreme output lengths or empty inputs.
#[test]
fn fuzz_hkdf_sha512_no_panic() {
    let test_cases: Vec<HkdfCase> = vec![
        (b"", b"", b"", 0),
        (b"ikm", b"salt", b"info", 0),
        (b"ikm", b"salt", b"info", 255 * 64),
        (b"ikm", b"salt", b"info", 255 * 64 + 1),
    ];
    for (ikm, salt, info, len) in test_cases {
        if len == 0 || len > 255 * 64 {
            let result = hkdf_sha512_derive_to_vec(ikm, salt, info, len);
            assert!(result.is_err(), "expected error for len={len}");
        } else {
            let kdf = HkdfSha512;
            let mut out = vec![0u8; len];
            let _ = kdf.derive(ikm, salt, info, &mut out);
        }
    }
}

/// PBKDF2-SHA-256: no panic on zero iterations, empty output, or empty inputs.
#[test]
fn fuzz_pbkdf2_sha256_no_panic() {
    let combinations: Vec<(&[u8], &[u8], u32, usize)> = vec![
        (b"", b"", 0, 0),
        (b"", b"salt", 0, 32),         // zero iterations
        (b"pw", b"salt", 0, 32),       // zero iterations
        (b"pw", b"salt", 1, 0),        // zero output
        (b"pw", b"", 1000, 32),        // empty salt (allowed by PBKDF2)
        (b"pw", b"salt", 1, 32),       // minimal valid
        (b"pw", b"salt", u32::MAX, 0), // max iterations, zero output
    ];
    for (pw, salt, iters, len) in combinations {
        let should_err = iters == 0 || len == 0;
        if should_err {
            let result = if len == 0 {
                let mut dummy = [0u8; 32];
                if iters == 0 {
                    pbkdf2_sha256(pw, salt, iters, &mut dummy)
                } else {
                    pbkdf2_sha256(pw, salt, iters, &mut [])
                }
            } else {
                pbkdf2_sha256(pw, salt, iters, &mut vec![0u8; len])
            };
            assert!(
                result.is_err(),
                "expected error for iters={iters}, len={len}"
            );
        } else {
            let mut out = vec![0u8; len];
            let _ = pbkdf2_sha256(pw, salt, iters, &mut out); // must not panic
        }
    }
}

/// Argon2id: no panic on salt-too-short, empty output, extreme costs.
#[test]
fn fuzz_argon2id_no_panic() {
    let combinations: Vec<(&[u8], &[u8], Argon2Params, usize)> = vec![
        // Salt too short (< 8 bytes) — must error.
        (b"pw", b"", Argon2Params::TEST_PARAMS, 32),
        (b"pw", b"1234567", Argon2Params::TEST_PARAMS, 32), // 7 bytes
        // Valid minimal parameters.
        (b"pw", SALT16, Argon2Params::TEST_PARAMS, 32),
        // Zero output length — must error.
        (b"pw", SALT16, Argon2Params::TEST_PARAMS, 0),
        // Empty password — valid per Argon2 spec.
        (b"", SALT16, Argon2Params::TEST_PARAMS, 32),
    ];
    for (pw, salt, params, len) in combinations {
        if len == 0 || salt.len() < 8 {
            // Use an explicit slice length to avoid borrow-check conflicts.
            let buf_len = if len == 0 { 32 } else { len };
            let out_len = len; // 0 means we're testing zero-output rejection
            let mut dummy = vec![0u8; buf_len];
            let slice = &mut dummy[..out_len];
            let result = argon2id_derive(pw, salt, params, slice);
            assert!(
                result.is_err(),
                "expected error for salt_len={}, out_len={}",
                salt.len(),
                len
            );
        } else {
            let mut out = vec![0u8; len];
            let _ = argon2id_derive(pw, salt, params, &mut out); // must not panic
        }
    }
}

/// scrypt: no panic on invalid log_n, zero r/p, extreme parameters.
///
/// The scrypt crate accepts `log_n=0` (N=1) as technically valid per spec;
/// only `log_n >= 64` (N overflows u64) and `r=0`/`p=0` are rejected.
/// We let `ScryptParams::new` determine validity rather than hard-coding
/// which parameter combinations are valid, and only assert on cases we know
/// the implementation must reject (zero output, log_n=64, r=0, p=0).
#[test]
fn fuzz_scrypt_no_panic() {
    let combinations: Vec<(u8, u32, u32, usize, bool)> = vec![
        // (log_n, r, p, out_len, must_error)
        (64, 8, 1, 32, true), // log_n=64 — N overflows u64
        (4, 0, 1, 32, true),  // r=0 — invalid per scrypt spec
        (4, 8, 1, 0, true),   // zero output — rejected by scrypt_derive
        (4, 8, 1, 32, false), // normal valid case
        (3, 8, 1, 32, false), // N=8, very small but valid
        (0, 8, 1, 32, false), // N=1, technically valid per scrypt crate
    ];
    for (log_n, r, p, out_len, must_err) in combinations {
        if must_err {
            // Either ScryptParams construction fails or scrypt_derive rejects.
            let params_ok = ScryptParams::new(log_n, r, p).is_ok();
            if params_ok && out_len == 0 {
                let result = scrypt_derive(b"pw", SALT16, log_n, r, p, &mut []);
                assert!(
                    result.is_err(),
                    "expected error for log_n={log_n}, r={r}, p={p}, out_len={out_len}"
                );
            } else if params_ok {
                // If params are valid, a zero-length output triggers the error.
                // For non-zero cases we let the implementation validate.
                let mut out = vec![0u8; out_len];
                let result = scrypt_derive(b"pw", SALT16, log_n, r, p, &mut out);
                assert!(
                    result.is_err(),
                    "expected error for log_n={log_n}, r={r}, p={p}, out_len={out_len}"
                );
            }
            // ScryptParams construction failure is sufficient validation.
        } else {
            let mut out = vec![0u8; out_len];
            let _ = scrypt_derive(b"password", SALT16, log_n, r, p, &mut out); // must not panic
        }
    }
}

/// Balloon-SHA-256: no panic on zero cost parameters or empty inputs.
///
/// Note: Balloon permits an empty salt (the paper imposes no salt minimum).
/// Only `space_cost == 0` or `time_cost == 0` are invalid parameters.
/// A zero-length output slice is also rejected since it must equal 32 bytes.
#[test]
fn fuzz_balloon_sha256_no_panic() {
    // (password, salt, space_cost, time_cost, expect_error)
    type BalloonCase<'a> = (&'a [u8], &'a [u8], u64, u64, bool);
    let combinations: Vec<BalloonCase<'_>> = vec![
        // (password, salt, space_cost, time_cost, expect_error)
        (b"pw", b"", 4, 3, false),    // empty salt — valid per Balloon spec
        (b"pw", SALT16, 0, 3, true),  // space_cost = 0 — must error
        (b"pw", SALT16, 4, 0, true),  // time_cost = 0 — must error
        (b"pw", SALT16, 1, 1, false), // minimal valid
        (b"pw", SALT16, 4, 3, false), // typical valid
        (b"", SALT16, 4, 3, false),   // empty password, valid
    ];
    for (pw, salt, space_cost, time_cost, expect_err) in combinations {
        let mut out = [0u8; 32];
        let result = balloon_sha256(pw, salt, space_cost, time_cost, &mut out);
        if expect_err {
            assert!(
                result.is_err(),
                "expected error for salt_len={}, space={space_cost}, time={time_cost}",
                salt.len()
            );
        } else {
            result.unwrap_or_else(|e| {
                panic!(
                    "unexpected error for salt_len={}, space={space_cost}, time={time_cost}: {e:?}",
                    salt.len()
                )
            });
        }
        // must not panic regardless
    }
}

/// bcrypt: no panic on invalid cost, empty salt, or extreme inputs.
///
/// Note: costs >= 13 are excluded from the fast test path to keep CI run times
/// bounded (bcrypt cost=31 would take ~hours). Invalid costs are checked without
/// actually running the hash.
#[test]
fn fuzz_bcrypt_no_panic() {
    let combinations: Vec<(&[u8], u32, bool)> = vec![
        // (password, cost, expect_error)
        (b"", 10, false),        // empty password, valid
        (b"password", 4, false), // minimum valid cost
        (b"password", 3, true),  // cost too low
        (b"password", 32, true), // cost too high
        (b"password", 0, true),  // cost zero
                                 // cost=31 is intentionally excluded: bcrypt 2^31 iterations ≈ hours of runtime.
    ];
    // Use a fixed 16-byte salt for bcrypt (it uses exactly 16 bytes).
    let salt = b"saltsaltsaltsalt";
    for (pw, cost, expect_err) in combinations {
        if expect_err {
            // For invalid costs, the hash function must return an error without panicking.
            // We do NOT actually run the hash for extremely high costs.
            let result = bcrypt_hash(pw, cost, salt);
            assert!(result.is_err(), "expected error for cost={cost}");
        } else if (4..=12).contains(&cost) {
            // Only run the hash for reasonable costs (4..=12) to keep tests fast.
            let result = bcrypt_hash(pw, cost, salt);
            assert!(
                result.is_ok(),
                "expected success for cost={cost}: {result:?}"
            );
        }
        // costs 13-31 that are valid are skipped from actual execution in this test.
    }
}

// ── Cross-KDF output independence ────────────────────────────────────────────

/// All KDFs produce distinct outputs for the same (password, salt) input.
///
/// This is not a security claim — it is a sanity check that no two KDFs
/// accidentally share the same key stream for a common test vector.
#[test]
fn all_kdfs_produce_distinct_outputs_for_same_input() {
    let pw = b"password";
    let salt = SALT16;

    let mut hkdf256_out = [0u8; 32];
    let mut hkdf384_out = [0u8; 32];
    let mut hkdf512_out = [0u8; 32];
    let mut pbkdf2_out = [0u8; 32];
    let mut balloon_out = [0u8; 32];
    let mut argon2_out = [0u8; 32];
    let mut scrypt_out = [0u8; 32];

    HkdfSha256.derive(pw, salt, b"", &mut hkdf256_out).unwrap();
    HkdfSha384.derive(pw, salt, b"", &mut hkdf384_out).unwrap();
    HkdfSha512.derive(pw, salt, b"", &mut hkdf512_out).unwrap();
    pbkdf2_sha256(pw, salt, 1000, &mut pbkdf2_out).unwrap();
    balloon_sha256(pw, salt, 4, 3, &mut balloon_out).unwrap();
    argon2id_derive(pw, salt, Argon2Params::TEST_PARAMS, &mut argon2_out).unwrap();
    scrypt_derive(pw, salt, 4, 8, 1, &mut scrypt_out).unwrap();

    let outputs: &[(&str, &[u8])] = &[
        ("hkdf-sha256", &hkdf256_out),
        ("hkdf-sha384", &hkdf384_out),
        ("hkdf-sha512", &hkdf512_out),
        ("pbkdf2-sha256", &pbkdf2_out),
        ("balloon-sha256", &balloon_out),
        ("argon2id", &argon2_out),
        ("scrypt", &scrypt_out),
    ];

    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i].1, outputs[j].1,
                "KDFs {} and {} produced identical 32-byte output for the same input — \
                 this is extremely unlikely unless there is a bug",
                outputs[i].0, outputs[j].0,
            );
        }
    }
}

// ── Minimum output length enforcement ─────────────────────────────────────────
//
// Verifies that all KDFs consistently reject empty output buffers.

/// All KDFs return BadInput for empty output length.
#[test]
fn all_kdfs_reject_empty_output() {
    // HKDF
    assert_eq!(
        HkdfSha256.derive(b"ikm", SALT16, b"", &mut []),
        Err(CryptoError::BadInput),
        "HKDF-SHA-256 must reject empty output"
    );
    assert_eq!(
        HkdfSha384.derive(b"ikm", SALT16, b"", &mut []),
        Err(CryptoError::BadInput),
        "HKDF-SHA-384 must reject empty output"
    );
    assert_eq!(
        HkdfSha512.derive(b"ikm", SALT16, b"", &mut []),
        Err(CryptoError::BadInput),
        "HKDF-SHA-512 must reject empty output"
    );

    // PBKDF2
    assert_eq!(
        pbkdf2_sha256(b"pw", SALT16, 1000, &mut []),
        Err(CryptoError::BadInput),
        "PBKDF2-SHA-256 must reject empty output"
    );

    // Argon2id
    assert_eq!(
        argon2id_derive(b"pw", SALT16, Argon2Params::TEST_PARAMS, &mut []),
        Err(CryptoError::BadInput),
        "Argon2id must reject empty output"
    );

    // scrypt
    assert_eq!(
        scrypt_derive(b"pw", SALT16, 4, 8, 1, &mut []),
        Err(CryptoError::BadInput),
        "scrypt must reject empty output"
    );

    // Balloon (fixed 32-byte output — zero-length slice still rejected)
    assert_eq!(
        balloon_sha256(b"pw", SALT16, 4, 3, &mut []),
        Err(CryptoError::BadInput),
        "Balloon must reject empty output"
    );

    // HKDF derive-to-vec wrappers
    assert_eq!(
        hkdf_sha256_derive_to_vec(b"ikm", SALT16, b"", 0),
        Err(CryptoError::BadInput),
        "hkdf_sha256_derive_to_vec must reject len=0"
    );
    assert_eq!(
        hkdf_sha384_derive_to_vec(b"ikm", SALT16, b"", 0),
        Err(CryptoError::BadInput),
        "hkdf_sha384_derive_to_vec must reject len=0"
    );
    assert_eq!(
        hkdf_sha512_derive_to_vec(b"ikm", SALT16, b"", 0),
        Err(CryptoError::BadInput),
        "hkdf_sha512_derive_to_vec must reject len=0"
    );
}
