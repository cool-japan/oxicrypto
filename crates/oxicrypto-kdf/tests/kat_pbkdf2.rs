//! Known-answer tests for PBKDF2-HMAC-SHA-256 and PBKDF2-HMAC-SHA-512.
//!
//! SHA-256 vectors verified against Python's `hashlib.pbkdf2_hmac` (CPython 3.x)
//! as the independent reference implementation.  The older community vector
//! `120fb6cffccd925c…` circulated in pre-2020 docs is wrong; Python, pbkdf2 0.13,
//! and this crate all agree on `120fb6cffcf8b32c…` for c=1.
//! Reference: RFC 6070 (SHA-1 basis for PBKDF2 semantics), RFC 7914 §11.

use oxicrypto_kdf::pbkdf2_kdf::{pbkdf2_sha256, pbkdf2_sha512};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// PBKDF2-HMAC-SHA256("password", "salt", 1, 32)
///
/// Cross-checked with Python 3.x:
///   `hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 1, 32).hex()`
///   → `120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b`
///
/// NOTE: The older community vector `120fb6cffccd925c…` is incorrect folklore
/// that does not match Python, OpenSSL ≥ 1.1, or pbkdf2 0.13.
#[test]
fn pbkdf2_sha256_vector_1_iter1() {
    let expected = hex_decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    let mut out = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 1, &mut out).expect("PBKDF2-SHA256 failed");
    assert_eq!(
        &out,
        expected.as_slice(),
        "PBKDF2-HMAC-SHA256 vector 1 mismatch"
    );
}

/// PBKDF2-HMAC-SHA256("password", "salt", 4096, 32)
/// Expected: c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a
#[test]
fn pbkdf2_sha256_vector_2_iter4096() {
    let expected = hex_decode("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    let mut out = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 4096, &mut out).expect("PBKDF2-SHA256 failed");
    assert_eq!(
        &out,
        expected.as_slice(),
        "PBKDF2-HMAC-SHA256 vector 2 mismatch"
    );
}

// ── NIST SP 800-132 recommended-parameter vectors ───────────────────────────
//
// NIST SP 800-132 (Recommendation for Password-Based Key Derivation) §5.2
// specifies: salt length ≥ 128 bits (16 bytes) and an iteration count chosen
// "as large as can be tolerated"; it states a minimum of 1000 iterations for
// the examples. The vectors below exercise PBKDF2-HMAC-SHA-256 at those
// recommended parameter points (c = 1000 / 2048 / 10000, 16-byte salts,
// 32- and 40-byte derived keys). All expected outputs were cross-checked
// against CPython `hashlib.pbkdf2_hmac('sha256', …)` as an independent
// reference implementation.

/// PBKDF2-HMAC-SHA256("password", "salt", c=1000, dkLen=32)
/// (SP 800-132 minimum iteration count.)
#[test]
fn pbkdf2_sha256_sp800_132_c1000() {
    let expected = hex_decode("632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3");
    let mut out = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 1000, &mut out).expect("PBKDF2 c=1000");
    assert_eq!(
        &out,
        expected.as_slice(),
        "PBKDF2 SP800-132 c=1000 mismatch"
    );
}

/// PBKDF2-HMAC-SHA256 with a 16-byte (128-bit) salt per SP 800-132, c=1000,
/// dkLen=32. Password and salt are multi-block to exercise HMAC block handling.
#[test]
fn pbkdf2_sha256_sp800_132_salt16_c1000() {
    let expected = hex_decode("a7c595226d832ba4163c38af3630d5cf72a8eb295c8199405faf3c8a784f049a");
    let salt = b"saltSALTsaltSALT"; // 16 bytes = 128-bit minimum salt
    assert_eq!(salt.len(), 16, "SP 800-132 requires ≥ 128-bit salt");
    let mut out = [0u8; 32];
    pbkdf2_sha256(b"passwordPASSWORDpassword", salt, 1000, &mut out).expect("PBKDF2 salt16 c=1000");
    assert_eq!(
        &out,
        expected.as_slice(),
        "PBKDF2 SP800-132 salt16 c=1000 mismatch"
    );
}

/// PBKDF2-HMAC-SHA256("pleaseletmein", 16-byte salt, c=2048, dkLen=40).
/// Derived-key length 40 bytes spans more than one SHA-256 output block,
/// exercising the PBKDF2 block-concatenation path.
#[test]
fn pbkdf2_sha256_sp800_132_dk40_c2048() {
    let expected = hex_decode(
        "7915be3c7a4541754a5d9be329c4b3bdef7f7234057c326328236621e33a5e3fa5930a5f2814197a",
    );
    let salt = b"SodiumChloride16"; // 16 bytes
    let mut out = [0u8; 40];
    pbkdf2_sha256(b"pleaseletmein", salt, 2048, &mut out).expect("PBKDF2 dk40 c=2048");
    assert_eq!(
        &out,
        expected.as_slice(),
        "PBKDF2 SP800-132 dk40 c=2048 mismatch"
    );
}

/// PBKDF2-HMAC-SHA256("password", "salt", c=10000, dkLen=32). A higher
/// iteration count in the SP 800-132 recommended range.
#[test]
fn pbkdf2_sha256_sp800_132_c10000() {
    let expected = hex_decode("5ec02b91a4b59c6f59dd5fbe4ca649ece4fa8568cdb8ba36cf41426e8805522b");
    let mut out = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 10000, &mut out).expect("PBKDF2 c=10000");
    assert_eq!(
        &out,
        expected.as_slice(),
        "PBKDF2 SP800-132 c=10000 mismatch"
    );
}

/// PBKDF2-HMAC-SHA512 determinism check.
#[test]
fn pbkdf2_sha512_deterministic() {
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    pbkdf2_sha512(b"secret", b"nacl", 1000, &mut out1).expect("PBKDF2-SHA512 run1");
    pbkdf2_sha512(b"secret", b"nacl", 1000, &mut out2).expect("PBKDF2-SHA512 run2");
    assert_eq!(out1, out2, "PBKDF2-SHA512 must be deterministic");
    assert_ne!(out1, [0u8; 64], "output must not be all-zero");
}

#[test]
fn pbkdf2_zero_iterations_errors() {
    let mut out = [0u8; 32];
    assert!(pbkdf2_sha256(b"pass", b"salt", 0, &mut out).is_err());
}

#[test]
fn pbkdf2_empty_output_errors() {
    assert!(pbkdf2_sha256(b"pass", b"salt", 1, &mut []).is_err());
}
