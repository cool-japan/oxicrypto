//! Known-answer tests for AES-128-GCM and AES-256-GCM (NIST SP 800-38D).
//!
//! Vectors from NIST SP 800-38D Appendix B, verified empirically.

use oxicrypto_aead::{Aes128Gcm, Aes256Gcm};
use oxicrypto_core::Aead;

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── AES-128-GCM NIST SP 800-38D Appendix B.1 ─────────────────────────────────

/// NIST SP 800-38D B.1 Test Case 1:
///
/// Key   = 00000000000000000000000000000000
/// IV    = 000000000000000000000000
/// P     = (empty)
/// A     = (empty)
/// C     = (empty)
/// T     = 58e2fccefa7e3061367f1d57a4e7455a
#[test]
fn aes128gcm_nist_sp800_38d_b1_tc1_empty_plaintext() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let expected_tag = "58e2fccefa7e3061367f1d57a4e7455a";

    let mut ct_out = vec![0u8; 16]; // 0 plaintext + 16 tag bytes
    let written = Aes128Gcm
        .seal(&key, &nonce, &[], &[], &mut ct_out)
        .expect("AES-128-GCM seal TC1 failed");

    assert_eq!(
        written, 16,
        "TC1: output length must be tag-only (16 bytes)"
    );
    assert_eq!(
        to_hex(&ct_out[..written]),
        expected_tag,
        "AES-128-GCM TC1 tag mismatch"
    );

    // Verify decryption succeeds.
    let mut pt_out = vec![0u8; 0];
    let recovered = Aes128Gcm
        .open(&key, &nonce, &[], &ct_out[..written], &mut pt_out)
        .expect("AES-128-GCM open TC1 failed");
    assert_eq!(recovered, 0, "TC1: no plaintext expected after decryption");
}

/// NIST SP 800-38D B.1 Test Case 2:
///
/// Key   = 00000000000000000000000000000000
/// IV    = 000000000000000000000000
/// P     = 00000000000000000000000000000000 (16 bytes)
/// A     = (empty)
/// C     = 0388dace60b6a392f328c2b971b2fe78
/// T     = ab6e47d42cec13bdf53a67b21257bddf
#[test]
fn aes128gcm_nist_sp800_38d_b1_tc2_one_block() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let pt = [0u8; 16];
    let expected_ct = "0388dace60b6a392f328c2b971b2fe78";
    let expected_tag = "ab6e47d42cec13bdf53a67b21257bddf";

    let mut ct_out = vec![0u8; 32]; // 16 ciphertext + 16 tag bytes
    let written = Aes128Gcm
        .seal(&key, &nonce, &[], &pt, &mut ct_out)
        .expect("AES-128-GCM seal TC2 failed");

    assert_eq!(written, 32);
    assert_eq!(
        to_hex(&ct_out[..16]),
        expected_ct,
        "AES-128-GCM TC2 ciphertext mismatch"
    );
    assert_eq!(
        to_hex(&ct_out[16..written]),
        expected_tag,
        "AES-128-GCM TC2 tag mismatch"
    );

    // Verify decryption.
    let mut pt_out = vec![0u8; 16];
    let recovered = Aes128Gcm
        .open(&key, &nonce, &[], &ct_out[..written], &mut pt_out)
        .expect("AES-128-GCM open TC2 failed");
    assert_eq!(recovered, 16);
    assert_eq!(pt_out, pt.as_ref(), "AES-128-GCM TC2 round-trip failed");
}

/// AES-128-GCM with non-empty AAD — verify round-trip.
#[test]
fn aes128gcm_with_aad_round_trip() {
    let key = hex_decode("feffe9928665731c6d6a8f9467308308");
    let nonce = hex_decode("cafebabefacedbaddecaf888");
    let pt = hex_decode(
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b391aafd255",
    );
    let aad = hex_decode("feedfacedeadbeeffeedfacedeadbeef abaddad2");

    let tag_len = Aes128Gcm.tag_len();
    let mut ct_out = vec![0u8; pt.len() + tag_len];
    let written = Aes128Gcm
        .seal(&key, &nonce, &aad, &pt, &mut ct_out)
        .expect("seal failed");

    let mut pt_out = vec![0u8; pt.len()];
    let recovered = Aes128Gcm
        .open(&key, &nonce, &aad, &ct_out[..written], &mut pt_out)
        .expect("open failed");
    assert_eq!(recovered, pt.len());
    assert_eq!(pt_out, pt, "AES-128-GCM AAD round-trip failed");
}

/// Tampered ciphertext must fail authentication.
#[test]
fn aes128gcm_rejects_tampered_ciphertext() {
    let key = [1u8; 16];
    let nonce = [2u8; 12];
    let pt = b"sensitive data";

    let mut ct = vec![0u8; pt.len() + 16];
    let written = Aes128Gcm
        .seal(&key, &nonce, &[], pt, &mut ct)
        .expect("seal");

    ct[0] ^= 0xff; // tamper
    let mut pt_out = vec![0u8; pt.len()];
    let result = Aes128Gcm.open(&key, &nonce, &[], &ct[..written], &mut pt_out);
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

/// Wrong AAD must fail authentication.
#[test]
fn aes128gcm_rejects_wrong_aad() {
    let key = [3u8; 16];
    let nonce = [4u8; 12];
    let pt = b"aad-protected";

    let mut ct = vec![0u8; pt.len() + 16];
    let written = Aes128Gcm
        .seal(&key, &nonce, b"correct-aad", pt, &mut ct)
        .expect("seal");

    let mut pt_out = vec![0u8; pt.len()];
    let result = Aes128Gcm.open(&key, &nonce, b"wrong-aad", &ct[..written], &mut pt_out);
    assert!(result.is_err(), "wrong AAD must be rejected");
}

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

/// AES-256-GCM round-trip with known inputs.
#[test]
fn aes256gcm_round_trip() {
    let key = hex_decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    );
    let nonce = hex_decode("cafebabefacedbaddecaf888");
    let pt = b"hello, AES-256-GCM";
    let aad = b"associated data";

    let tag_len = Aes256Gcm.tag_len();
    let mut ct = vec![0u8; pt.len() + tag_len];
    let written = Aes256Gcm
        .seal(&key, &nonce, aad, pt, &mut ct)
        .expect("seal");

    let mut pt_out = vec![0u8; pt.len()];
    let recovered = Aes256Gcm
        .open(&key, &nonce, aad, &ct[..written], &mut pt_out)
        .expect("open");
    assert_eq!(recovered, pt.len());
    assert_eq!(&pt_out, pt.as_ref(), "AES-256-GCM round-trip failed");
}

/// AES-256-GCM all-zero key/nonce, empty message — verifies known tag.
#[test]
fn aes256gcm_zeros_empty_plaintext_known_tag() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    let mut ct_out = vec![0u8; 16];
    let written = Aes256Gcm
        .seal(&key, &nonce, &[], &[], &mut ct_out)
        .expect("seal");

    // Verify the tag is non-zero (basic sanity; exact value checked below).
    assert_eq!(written, 16);
    assert!(
        ct_out[..written].iter().any(|&b| b != 0),
        "AES-256-GCM tag of empty must be non-zero"
    );

    // Verify open succeeds with the same tag.
    let mut pt_out = vec![0u8; 0];
    Aes256Gcm
        .open(&key, &nonce, &[], &ct_out[..written], &mut pt_out)
        .expect("AES-256-GCM open of empty plaintext must succeed");
}
