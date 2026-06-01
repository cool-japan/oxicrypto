//! Known-answer tests for AES-GCM-SIV (RFC 8452 Appendix C).
//!
//! These vectors are transcribed verbatim from RFC 8452 Appendix C.1
//! (AEAD_AES_128_GCM_SIV) and C.2 (AEAD_AES_256_GCM_SIV). Each RFC "Result"
//! value is exactly `ciphertext ‖ tag`, so every vector drives `seal`
//! (asserting the exact result bytes) and `open` (asserting the exact
//! recovered plaintext). The empty-plaintext cases authenticate the nonce /
//! AAD with no message bytes (result is the 16-byte tag alone).

use oxicrypto_aead::{AesGcmSiv128, AesGcmSiv256};

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Drive one AES-128-GCM-SIV RFC 8452 C.1 vector: seal must produce exactly
/// `expected_result` (= ciphertext ‖ tag) and open must recover the plaintext.
fn check_128(
    key_hex: &str,
    nonce_hex: &str,
    aad_hex: &str,
    pt_hex: &str,
    expected_result_hex: &str,
) {
    let key: [u8; 16] = hex_decode(key_hex).try_into().expect("128-bit key");
    let nonce: [u8; 12] = hex_decode(nonce_hex).try_into().expect("96-bit nonce");
    let aad = hex_decode(aad_hex);
    let pt = hex_decode(pt_hex);

    let cipher = AesGcmSiv128;
    let mut ct = vec![0u8; pt.len() + AesGcmSiv128::TAG_LEN];
    let written = cipher.seal(&key, &nonce, &aad, &pt, &mut ct).expect("seal");
    assert_eq!(written, pt.len() + 16, "C.1 output length");
    assert_eq!(
        to_hex(&ct[..written]),
        expected_result_hex.replace(' ', ""),
        "RFC 8452 C.1 result (ct ‖ tag) mismatch"
    );

    let mut dec = vec![0u8; pt.len()];
    let n = cipher
        .open(&key, &nonce, &aad, &ct[..written], &mut dec)
        .expect("open");
    assert_eq!(n, pt.len());
    assert_eq!(
        to_hex(&dec),
        to_hex(&pt),
        "RFC 8452 C.1 round-trip mismatch"
    );
}

/// Drive one AES-256-GCM-SIV RFC 8452 C.2 vector.
fn check_256(
    key_hex: &str,
    nonce_hex: &str,
    aad_hex: &str,
    pt_hex: &str,
    expected_result_hex: &str,
) {
    let key: [u8; 32] = hex_decode(key_hex).try_into().expect("256-bit key");
    let nonce: [u8; 12] = hex_decode(nonce_hex).try_into().expect("96-bit nonce");
    let aad = hex_decode(aad_hex);
    let pt = hex_decode(pt_hex);

    let cipher = AesGcmSiv256;
    let mut ct = vec![0u8; pt.len() + AesGcmSiv256::TAG_LEN];
    let written = cipher.seal(&key, &nonce, &aad, &pt, &mut ct).expect("seal");
    assert_eq!(written, pt.len() + 16, "C.2 output length");
    assert_eq!(
        to_hex(&ct[..written]),
        expected_result_hex.replace(' ', ""),
        "RFC 8452 C.2 result (ct ‖ tag) mismatch"
    );

    let mut dec = vec![0u8; pt.len()];
    let n = cipher
        .open(&key, &nonce, &aad, &ct[..written], &mut dec)
        .expect("open");
    assert_eq!(n, pt.len());
    assert_eq!(
        to_hex(&dec),
        to_hex(&pt),
        "RFC 8452 C.2 round-trip mismatch"
    );
}

// ── AES-128-GCM-SIV: RFC 8452 Appendix C.1 ───────────────────────────────────

/// Empty plaintext, empty AAD — authenticates the nonce only (result = tag).
#[test]
fn aes128_gcm_siv_c1_empty() {
    check_128(
        "01000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "",
        "dc20e2d83f25705bb49e439eca56de25",
    );
}

/// 8-byte plaintext, no AAD.
#[test]
fn aes128_gcm_siv_c1_pt8() {
    check_128(
        "01000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "0100000000000000",
        "b5d839330ac7b786578782fff6013b815b287c22493a364c",
    );
}

/// 16-byte plaintext (one block), no AAD.
#[test]
fn aes128_gcm_siv_c1_pt16() {
    check_128(
        "01000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "01000000000000000000000000000000",
        "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4",
    );
}

/// 32-byte plaintext (two blocks), no AAD.
#[test]
fn aes128_gcm_siv_c1_pt32() {
    check_128(
        "01000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "01000000000000000000000000000000\
         02000000000000000000000000000000",
        "84e07e62ba83a6585417245d7ec413a9\
         fe427d6315c09b57ce45f2e3936a9445\
         1a8e45dcd4578c667cd86847bf6155ff",
    );
}

/// 8-byte plaintext with 1-byte AAD (AAD authentication path).
#[test]
fn aes128_gcm_siv_c1_pt8_aad1() {
    check_128(
        "01000000000000000000000000000000",
        "030000000000000000000000",
        "01",
        "0200000000000000",
        "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508",
    );
}

/// 16-byte plaintext with 1-byte AAD.
#[test]
fn aes128_gcm_siv_c1_pt16_aad1() {
    check_128(
        "01000000000000000000000000000000",
        "030000000000000000000000",
        "01",
        "02000000000000000000000000000000",
        "e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f",
    );
}

// ── AES-256-GCM-SIV: RFC 8452 Appendix C.2 ───────────────────────────────────

/// Empty plaintext, empty AAD — authenticates the nonce only (result = tag).
#[test]
fn aes256_gcm_siv_c2_empty() {
    check_256(
        "01000000000000000000000000000000\
         00000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "",
        "07f5f4169bbf55a8400cd47ea6fd400f",
    );
}

/// 8-byte plaintext, no AAD.
#[test]
fn aes256_gcm_siv_c2_pt8() {
    check_256(
        "01000000000000000000000000000000\
         00000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "0100000000000000",
        "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
    );
}

/// 16-byte plaintext (one block), no AAD.
#[test]
fn aes256_gcm_siv_c2_pt16() {
    check_256(
        "01000000000000000000000000000000\
         00000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "01000000000000000000000000000000",
        "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
    );
}

/// 32-byte plaintext (two blocks), no AAD.
#[test]
fn aes256_gcm_siv_c2_pt32() {
    check_256(
        "01000000000000000000000000000000\
         00000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "01000000000000000000000000000000\
         02000000000000000000000000000000",
        "4a6a9db4c8c6549201b9edb53006cba8\
         21ec9cf850948a7c86c68ac7539d027f\
         e819e63abcd020b006a976397632eb5d",
    );
}

/// 16-byte plaintext with 1-byte AAD.
#[test]
fn aes256_gcm_siv_c2_pt16_aad1() {
    check_256(
        "01000000000000000000000000000000\
         00000000000000000000000000000000",
        "030000000000000000000000",
        "01",
        "02000000000000000000000000000000",
        "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
    );
}

// ── Negative cases ────────────────────────────────────────────────────────────

#[test]
fn aes128_gcm_siv_with_aad() {
    // Additional round-trip test with non-empty AAD
    let key: [u8; 16] = [0x01; 16];
    let nonce: [u8; 12] = [0x02; 12];
    let pt = b"hello, gcm-siv!";
    let aad = b"authenticated associated data";

    let cipher = AesGcmSiv128;
    let mut ct = vec![0u8; pt.len() + AesGcmSiv128::TAG_LEN];
    let written = cipher.seal(&key, &nonce, aad, pt, &mut ct).expect("seal");

    let mut dec = vec![0u8; pt.len()];
    let n = cipher
        .open(&key, &nonce, aad, &ct[..written], &mut dec)
        .expect("open");
    assert_eq!(&dec[..n], pt.as_ref());
}

#[test]
fn aes128_gcm_siv_wrong_key_fails() {
    let key: [u8; 16] = [0x01; 16];
    let nonce: [u8; 12] = [0x02; 12];
    let pt = b"test";

    let cipher = AesGcmSiv128;
    let mut ct = vec![0u8; pt.len() + AesGcmSiv128::TAG_LEN];
    let written = cipher.seal(&key, &nonce, b"", pt, &mut ct).expect("seal");

    let wrong_key: [u8; 16] = [0xff; 16];
    let mut dec = vec![0u8; pt.len()];
    assert!(cipher
        .open(&wrong_key, &nonce, b"", &ct[..written], &mut dec)
        .is_err());
}

#[test]
fn aes256_gcm_siv_tampered_ct_fails() {
    let key: [u8; 32] = [0x42; 32];
    let nonce: [u8; 12] = [0x24; 12];
    let pt = b"sensitive data";

    let cipher = AesGcmSiv256;
    let mut ct = vec![0u8; pt.len() + AesGcmSiv256::TAG_LEN];
    let written = cipher.seal(&key, &nonce, b"", pt, &mut ct).expect("seal");
    ct[0] ^= 0x01; // tamper

    let mut dec = vec![0u8; pt.len()];
    assert!(cipher
        .open(&key, &nonce, b"", &ct[..written], &mut dec)
        .is_err());
}

/// Flipping a tag byte on an empty-plaintext (tag-only) C.1 result must be
/// rejected as `InvalidTag`.
#[test]
fn aes128_gcm_siv_c1_empty_tag_tamper_rejected() {
    use oxicrypto_core::CryptoError;
    let key: [u8; 16] = hex_decode("01000000000000000000000000000000")
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = hex_decode("030000000000000000000000").try_into().unwrap();
    let mut result = hex_decode("dc20e2d83f25705bb49e439eca56de25");
    result[0] ^= 0xff; // flip a tag byte
    let cipher = AesGcmSiv128;
    let mut dec = vec![0u8; 0];
    assert_eq!(
        cipher.open(&key, &nonce, b"", &result, &mut dec),
        Err(CryptoError::InvalidTag),
        "tampered tag-only result must be rejected"
    );
}
