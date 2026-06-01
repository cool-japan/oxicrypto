//! PBKDF2-HMAC-SHA-256 extended tests: RFC 8018 / SP 800-132 context.
//!
//! RFC 8018 Section 5.2 specifies PBKDF2, but its concrete test vectors
//! (Appendix B) use HMAC-SHA-1.  Since SHA-1 is not exposed by this crate,
//! we instead test PBKDF2-HMAC-SHA-256 properties and cross-verified KATs.
//!
//! Reference values for SHA-256 come from Python 3.x:
//!   `hashlib.pbkdf2_hmac('sha256', P, S, c, dkLen).hex()`
//!
//! The c=1 / dkLen=32 vector (`120fb6cffcf8b32c…`) already exists in
//! `kat_pbkdf2.rs` and is not duplicated here.  This file covers:
//! - c=2, dkLen=32  (two-iteration round)
//! - c=1, dkLen=64  (output crossing multiple HMAC blocks)
//! - Long password, long salt
//! - Parameter boundary: c=0 must error
//! - Parameter boundary: dkLen=0 must error
//! - Different iteration counts produce different output
//! - Different salt lengths produce different output

use oxicrypto_kdf::pbkdf2_kdf::pbkdf2_sha256;

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// ── Known-answer test: c=2, dkLen=32 ─────────────────────────────────────────

/// PBKDF2-HMAC-SHA256("password", "salt", 2, 32)
///
/// Python 3.x reference:
///   hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 2, 32).hex()
///   → ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
#[test]
fn pbkdf2_sha256_c2_dklen32() {
    let expected = hex_decode("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    let mut out = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 2, &mut out).expect("PBKDF2-SHA256 c=2 failed");
    assert_eq!(
        to_hex(&out),
        to_hex(expected.as_slice()),
        "PBKDF2-HMAC-SHA256 c=2 dkLen=32 mismatch"
    );
}

// ── Known-answer test: c=1, dkLen=64 — crosses two HMAC-SHA-256 blocks ──────

/// PBKDF2-HMAC-SHA256("password", "salt", 1, 64)
///
/// Cross-verified: first 32 bytes must match the c=1 dkLen=32 vector from
/// `kat_pbkdf2.rs`, since PBKDF2 blocks are computed independently.
/// Second block (bytes 32–63) must be non-zero.
#[test]
fn pbkdf2_sha256_c1_dklen64_first32_matches_dklen32() {
    let mut out64 = [0u8; 64];
    pbkdf2_sha256(b"password", b"salt", 1, &mut out64).expect("dkLen=64 failed");

    let mut out32 = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 1, &mut out32).expect("dkLen=32 failed");

    // By PBKDF2 construction: DK[0..32] (dkLen=64) == DK[0..32] (dkLen=32)
    assert_eq!(&out64[..32], &out32[..], "first block must be identical");
    // Second block must not be zero
    assert_ne!(out64[32..], [0u8; 32]);
}

// ── Long password and long salt ───────────────────────────────────────────────

/// Long password + long salt, c=4096, dkLen=32.
///
/// The expected value `348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1`
/// matches the output of Python 3.x:
///   `hashlib.pbkdf2_hmac('sha256', b'passwordPASSWORDpassword',`
///   `                    b'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 32).hex()`
/// (independently checked via Python 3.12 `hashlib`).
#[test]
fn pbkdf2_sha256_long_password_salt_c4096() {
    let expected = hex_decode("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1");
    let mut out = [0u8; 32];
    pbkdf2_sha256(
        b"passwordPASSWORDpassword",
        b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        4096,
        &mut out,
    )
    .expect("long password/salt failed");
    assert_eq!(
        to_hex(&out),
        to_hex(expected.as_slice()),
        "PBKDF2-HMAC-SHA256 long P/S c=4096 mismatch"
    );
}

// ── Property tests ────────────────────────────────────────────────────────────

/// Different iteration counts must produce different derived keys.
#[test]
fn pbkdf2_sha256_iterations_change_output() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 1, &mut out1).unwrap();
    pbkdf2_sha256(b"password", b"salt", 2, &mut out2).unwrap();
    assert_ne!(out1, out2, "different c must produce different DK");
}

/// Different salts must produce different derived keys.
#[test]
fn pbkdf2_sha256_salt_changes_output() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt-a", 1, &mut out1).unwrap();
    pbkdf2_sha256(b"password", b"salt-b", 1, &mut out2).unwrap();
    assert_ne!(out1, out2, "different salts must produce different DK");
}

/// Different passwords must produce different derived keys.
#[test]
fn pbkdf2_sha256_password_changes_output() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    pbkdf2_sha256(b"password1", b"salt", 1, &mut out1).unwrap();
    pbkdf2_sha256(b"password2", b"salt", 1, &mut out2).unwrap();
    assert_ne!(out1, out2, "different passwords must produce different DK");
}

/// PBKDF2 must be deterministic.
#[test]
fn pbkdf2_sha256_deterministic() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 1000, &mut out1).unwrap();
    pbkdf2_sha256(b"password", b"salt", 1000, &mut out2).unwrap();
    assert_eq!(out1, out2, "PBKDF2 must be deterministic");
}

// ── Parameter boundary tests ──────────────────────────────────────────────────

/// c=0 must return an error.
#[test]
fn pbkdf2_sha256_zero_iterations_errors() {
    let mut out = [0u8; 32];
    assert!(
        pbkdf2_sha256(b"password", b"salt", 0, &mut out).is_err(),
        "c=0 must return an error"
    );
}

/// dkLen=0 must return an error.
#[test]
fn pbkdf2_sha256_empty_output_errors() {
    assert!(
        pbkdf2_sha256(b"password", b"salt", 1, &mut []).is_err(),
        "dkLen=0 must return an error"
    );
}
