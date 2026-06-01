//! Known-answer tests for scrypt.
//!
//! Test vectors from RFC 7914 §12.

use oxicrypto_kdf::scrypt_kdf::scrypt_derive;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 7914 §12 Test Vector #1:
/// scrypt("", "", N=16, r=1, p=1, dkLen=64)
/// Expected:
///   77d6576238657b203b19ca42c18a0497
///   f16b4844e3074ae8dfdffa3fede21442
///   fcd0069ded0948f8326a753a0fc81f17
///   e8d3e0fb2e0d3628cf35e20c38d18906
///
/// Note: N=16 means log_n=4 (2^4=16). This is RFC 7914's smallest vector.
#[test]
fn scrypt_rfc7914_vector_1() {
    let expected = hex_decode(
        "77d6576238657b203b19ca42c18a0497\
         f16b4844e3074ae8dfdffa3fede21442\
         fcd0069ded0948f8326a753a0fc81f17\
         e8d3e0fb2e0d3628cf35e20c38d18906",
    );
    let mut out = vec![0u8; 64];
    scrypt_derive(b"", b"", 4, 1, 1, &mut out).expect("scrypt vector 1 failed");
    assert_eq!(out, expected, "scrypt RFC7914 vector 1 mismatch");
}

/// RFC 7914 §12 Test Vector #2:
/// scrypt("password", "NaCl", N=1024, r=8, p=16, dkLen=64)
/// Expected:
///   fdbabe1c9d3472007856e7190d01e9fe
///   7c6ad7cbc8237830e77376634b373162
///   2eaf30d92e22a3886ff109279d9830da
///   c727afb94a83ee6d8360cbdfa2cc0640
///
/// Note: N=1024 means log_n=10. This test may take ~500ms on slower machines.
#[test]
fn scrypt_rfc7914_vector_2() {
    let expected = hex_decode(
        "fdbabe1c9d3472007856e7190d01e9fe\
         7c6ad7cbc8237830e77376634b373162\
         2eaf30d92e22a3886ff109279d9830da\
         c727afb94a83ee6d8360cbdfa2cc0640",
    );
    let mut out = vec![0u8; 64];
    scrypt_derive(b"password", b"NaCl", 10, 8, 16, &mut out).expect("scrypt vector 2 failed");
    assert_eq!(out, expected, "scrypt RFC7914 vector 2 mismatch");
}

/// RFC 7914 §12 Test Vector #3:
/// scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, dkLen=64)
/// Expected:
///   7023bdcb3afd7348461c06cd81fd38eb
///   fda8fbba904f8e3ea9b543f6545da1f2
///   d5432955613f0fcf62d49705242a9af9
///   e61e85dc0d651e40dfcf017b45575887
///
/// Note: N=16384 means log_n=14. Cross-checked against CPython
/// `hashlib.scrypt` (OpenSSL) as an independent reference implementation.
/// This vector takes a few hundred ms; it runs by default.
#[test]
fn scrypt_rfc7914_vector_3() {
    let expected = hex_decode(
        "7023bdcb3afd7348461c06cd81fd38eb\
         fda8fbba904f8e3ea9b543f6545da1f2\
         d5432955613f0fcf62d49705242a9af9\
         e61e85dc0d651e40dfcf017b45575887",
    );
    let mut out = vec![0u8; 64];
    scrypt_derive(b"pleaseletmein", b"SodiumChloride", 14, 8, 1, &mut out)
        .expect("scrypt vector 3 failed");
    assert_eq!(out, expected, "scrypt RFC7914 vector 3 mismatch");
}

/// RFC 7914 §12 Test Vector #4:
/// scrypt("pleaseletmein", "SodiumChloride", N=1048576, r=8, p=1, dkLen=64)
/// Expected:
///   2101cb9b6a511aaeaddbbe09cf70f881
///   ec568d574a2ffd4dabe5ee9820adaa47
///   8e56fd8f4ba5d09ffa1c6d927c40f4c3
///   37304049e8a952fbcbf45c6fa77a41a4
///
/// Note: N=1048576 means log_n=20, requiring ≈ 1 GiB of working memory and
/// several seconds of CPU. It is **gated behind `#[ignore]`** so the default
/// test run stays fast and within memory; it is NOT silently skipped. Run it
/// explicitly with:
///
/// ```text
/// cargo test -p oxicrypto-kdf --all-features --test kat_scrypt \
///     -- --ignored scrypt_rfc7914_vector_4_1gib
/// ```
///
/// (Prefer `--release` for acceptable runtime.) Expected output cross-checked
/// against CPython `hashlib.scrypt` (OpenSSL).
#[test]
#[ignore = "needs ~1 GiB RAM and several seconds; run explicitly with --ignored"]
fn scrypt_rfc7914_vector_4_1gib() {
    let expected = hex_decode(
        "2101cb9b6a511aaeaddbbe09cf70f881\
         ec568d574a2ffd4dabe5ee9820adaa47\
         8e56fd8f4ba5d09ffa1c6d927c40f4c3\
         37304049e8a952fbcbf45c6fa77a41a4",
    );
    let mut out = vec![0u8; 64];
    scrypt_derive(b"pleaseletmein", b"SodiumChloride", 20, 8, 1, &mut out)
        .expect("scrypt vector 4 failed");
    assert_eq!(out, expected, "scrypt RFC7914 vector 4 mismatch");
}

/// Determinism check.
#[test]
fn scrypt_deterministic() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    scrypt_derive(b"key", b"salt", 4, 8, 1, &mut out1).expect("scrypt run 1");
    scrypt_derive(b"key", b"salt", 4, 8, 1, &mut out2).expect("scrypt run 2");
    assert_eq!(out1, out2, "scrypt must be deterministic");
}

/// Empty output should error.
#[test]
fn scrypt_empty_output_errors() {
    assert!(scrypt_derive(b"pass", b"salt", 4, 8, 1, &mut []).is_err());
}
